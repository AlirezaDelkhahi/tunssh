package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
	"github.com/AlirezaDelkhahi/tunssh/internal/sshclient"
	"github.com/AlirezaDelkhahi/tunssh/internal/tun"
)

const (
	rpcMethodPrepareSnapshot = "prepare_snapshot"
	rpcMethodStartTUN        = "start_tun"
	rpcMethodSetBypass       = "set_bypass"
	rpcMethodStop            = "stop"
	rpcMethodStats           = "stats"
	rpcMethodRestoreSnapshot = "restore_snapshot"
	rpcMethodCheckActive     = "check_active"

	maxIPCFrameBytes     = 4 * 1024 * 1024
	rpcDialTimeout       = 30 * time.Second
	rpcStatsTimeout      = 2 * time.Second
	rpcStopTimeout       = 15 * time.Second
	dialHandshakeTimeout = 30 * time.Second
	helperCleanupTimeout = 15 * time.Second
)

type helperLauncher interface {
	Launch(ctx context.Context) (io.ReadWriteCloser, func(), error)
}

type rpcRequest struct {
	Method        string                      `json:"method"`
	Start         *TUNStartRequest            `json:"start,omitempty"`
	BypassIranLAN *bool                       `json:"bypass_iran_lan,omitempty"`
	Snapshot      *splitroute.NetworkSnapshot `json:"snapshot,omitempty"`
}

type rpcResponse struct {
	OK                 bool                        `json:"ok"`
	Error              string                      `json:"error,omitempty"`
	RollbackIncomplete bool                        `json:"rollback_incomplete,omitempty"`
	Snapshot           *splitroute.NetworkSnapshot `json:"snapshot,omitempty"`
	Stats              *tun.Stats                  `json:"stats,omitempty"`
	Active             *bool                       `json:"active,omitempty"`
}

type helperRPCError struct {
	msg                string
	rollbackIncomplete bool
}

func (e *helperRPCError) Error() string {
	return e.msg
}

func (e *helperRPCError) Unwrap() error {
	if e.rollbackIncomplete {
		return ErrTUNRollbackIncomplete
	}
	return nil
}

type dialReq struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type dialResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type slogYamuxLogger struct {
	logger *slog.Logger
}

func (l slogYamuxLogger) Print(v ...interface{}) {
	if l.logger != nil {
		l.logger.Debug("yamux", "msg", fmt.Sprint(v...))
	}
}

func (l slogYamuxLogger) Printf(format string, v ...interface{}) {
	if l.logger != nil {
		l.logger.Debug("yamux", "msg", fmt.Sprintf(format, v...))
	}
}

func (l slogYamuxLogger) Println(v ...interface{}) {
	if l.logger != nil {
		l.logger.Debug("yamux", "msg", fmt.Sprint(v...))
	}
}

func newYamuxConfig(logger *slog.Logger) *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.StreamOpenTimeout = 10 * time.Second
	cfg.StreamCloseTimeout = 30 * time.Second
	if logger != nil {
		cfg.LogOutput = nil
		cfg.Logger = slogYamuxLogger{logger: logger}
	} else {
		cfg.LogOutput = io.Discard
		cfg.Logger = nil
	}
	return cfg
}

func writeFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ipc: marshal frame: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxIPCFrameBytes {
		return fmt.Errorf("ipc: frame length %d out of bounds", len(payload))
	}

	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(payload)))
	copy(frame[4:], payload)

	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func readFrame(r io.Reader, dst any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size == 0 || size > maxIPCFrameBytes {
		return fmt.Errorf("ipc: invalid frame size %d", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	if err := json.Unmarshal(buf, dst); err != nil {
		return fmt.Errorf("ipc: unmarshal frame: %w", err)
	}
	return nil
}

// yamuxStreamConn wraps *yamux.Stream to expose TCP-compatible CloseWrite/CloseRead half-close
// semantics (using yamux.Stream.Close for FIN while unblocking readers on full Close).
type yamuxStreamConn struct {
	*yamux.Stream
	closed atomic.Bool
}

func (c *yamuxStreamConn) Read(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, err := c.Stream.Read(b)
	if err != nil && c.closed.Load() {
		return n, net.ErrClosed
	}
	return n, err
}

func (c *yamuxStreamConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.Stream.Write(b)
}

func (c *yamuxStreamConn) SetDeadline(t time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Stream.SetDeadline(t)
}

func (c *yamuxStreamConn) SetReadDeadline(t time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Stream.SetReadDeadline(t)
}

func (c *yamuxStreamConn) SetWriteDeadline(t time.Time) error {
	if c.closed.Load() {
		return net.ErrClosed
	}
	return c.Stream.SetWriteDeadline(t)
}

func (c *yamuxStreamConn) CloseWrite() error {
	return c.Stream.Close()
}

func (c *yamuxStreamConn) CloseRead() error {
	_ = c.Stream.SetReadDeadline(time.Unix(1, 0))
	return nil
}

func (c *yamuxStreamConn) Close() error {
	c.closed.Store(true)
	_ = c.Stream.SetReadDeadline(time.Unix(1, 0))
	return c.Stream.Close()
}

type yamuxTunnelDialer struct {
	sess *yamux.Session
}

func (d *yamuxTunnelDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d == nil || d.sess == nil || d.sess.IsClosed() {
		return nil, net.ErrClosed
	}

	stream, err := d.sess.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("ipc: open dial stream: %w", err)
	}

	stopWatch := context.AfterFunc(ctx, func() {
		_ = stream.SetDeadline(time.Unix(1, 0))
		_ = stream.Close()
	})
	cleanupWatch := func() bool {
		return stopWatch()
	}

	deadline := time.Now().Add(dialHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = stream.SetDeadline(deadline)

	if err := writeFrame(stream, dialReq{Network: network, Address: address}); err != nil {
		stillActive := cleanupWatch()
		_ = stream.SetReadDeadline(time.Unix(1, 0))
		_ = stream.Close()
		if !stillActive && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ipc: send dial request: %w", err)
	}

	var resp dialResp
	if err := readFrame(stream, &resp); err != nil {
		stillActive := cleanupWatch()
		_ = stream.SetReadDeadline(time.Unix(1, 0))
		_ = stream.Close()
		if !stillActive && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("ipc: read dial response: %w", err)
	}

	if !cleanupWatch() && ctx.Err() != nil {
		_ = stream.SetReadDeadline(time.Unix(1, 0))
		_ = stream.Close()
		return nil, ctx.Err()
	}
	_ = stream.SetDeadline(time.Time{})

	if !resp.OK || resp.Error != "" {
		_ = stream.SetReadDeadline(time.Unix(1, 0))
		_ = stream.Close()
		if resp.Error != "" {
			return nil, errors.New(resp.Error)
		}
		return nil, errors.New("ipc: remote dial failed")
	}

	return &yamuxStreamConn{Stream: stream}, nil
}

// RunHelperOnConn serves RPC control streams over conn using yamux.Server and proxies outbound
// tunnel dials back through yamux streams. If the session closes unexpectedly while TUN is active
// (e.g., unprivileged GUI crashed), it immediately stops TUN and restores routes/DNS without
// touching recovery_state.json.
func RunHelperOnConn(ctx context.Context, conn io.ReadWriteCloser, ctrl TUNSessionController, logger *slog.Logger) error {
	ctx = normalizeContext(ctx)
	if conn == nil {
		return errors.New("ipc: connection must not be nil")
	}
	if ctrl == nil {
		return errors.New("ipc: controller must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	sess, err := yamux.Server(conn, newYamuxConfig(logger))
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("ipc: create yamux server: %w", err)
	}

	acceptDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = sess.Close()
			_ = conn.Close()
		case <-acceptDone:
		}
	}()

	dialer := &yamuxTunnelDialer{sess: sess}
	var tunActive atomic.Bool
	var rpcWG sync.WaitGroup

	for {
		stream, acceptErr := sess.AcceptStream()
		if acceptErr != nil {
			break
		}
		rpcWG.Add(1)
		go func(st *yamux.Stream) {
			defer rpcWG.Done()
			handleHelperRPCStream(ctx, sess.CloseChan(), st, ctrl, dialer, &tunActive)
		}(stream)
	}

	close(acceptDone)
	rpcWG.Wait()

	if tunActive.Load() || ctrl.Stats().Running {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), helperCleanupTimeout)
		defer cancel()
		if stopErr := ctrl.Stop(cleanupCtx); stopErr != nil {
			logger.Error("tun helper crash cleanup failed", "error", stopErr)
		}
	}

	_ = sess.Close()
	_ = conn.Close()
	return nil
}

func handleHelperRPCStream(
	baseCtx context.Context,
	sessClosed <-chan struct{},
	st *yamux.Stream,
	ctrl TUNSessionController,
	dialer sshclient.TunnelDialer,
	tunActive *atomic.Bool,
) {
	defer func() {
		_ = st.SetReadDeadline(time.Unix(1, 0))
		_ = st.Close()
	}()

	var req rpcRequest
	if err := readFrame(st, &req); err != nil {
		return
	}

	opCtx, cancel := context.WithCancel(baseCtx)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	if sessClosed != nil && (req.Method == rpcMethodPrepareSnapshot || req.Method == rpcMethodStartTUN || req.Method == rpcMethodSetBypass) {
		go func() {
			select {
			case <-sessClosed:
				cancel()
			case <-done:
			}
		}()
	}

	var resp rpcResponse
	switch req.Method {
	case rpcMethodPrepareSnapshot:
		snap, err := ctrl.PrepareSession(opCtx)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
			resp.Snapshot = &snap
		}

	case rpcMethodStartTUN:
		if req.Start == nil {
			resp.Error = "ipc: start_tun missing request payload"
		} else if err := ctrl.StartTUN(opCtx, *req.Start, dialer); err != nil {
			resp.Error = err.Error()
			resp.RollbackIncomplete = errors.Is(err, ErrTUNRollbackIncomplete)
		} else {
			tunActive.Store(true)
			resp.OK = true
		}

	case rpcMethodSetBypass:
		if req.BypassIranLAN == nil {
			resp.Error = "ipc: set_bypass missing bypass_iran_lan flag"
		} else if err := ctrl.SetBypass(opCtx, *req.BypassIranLAN); err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	case rpcMethodStop:
		if err := ctrl.Stop(opCtx); err != nil {
			resp.Error = err.Error()
		} else {
			tunActive.Store(false)
			resp.OK = true
		}

	case rpcMethodStats:
		stVal := ctrl.Stats()
		resp.OK = true
		resp.Stats = &stVal

	case rpcMethodRestoreSnapshot:
		if req.Snapshot == nil {
			resp.Error = "ipc: restore_snapshot missing snapshot payload"
		} else if err := ctrl.RestoreFromSnapshot(opCtx, *req.Snapshot); err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
		}

	case rpcMethodCheckActive:
		active, err := ctrl.IsActiveOnOS(opCtx)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.OK = true
			resp.Active = &active
		}

	default:
		resp.Error = fmt.Sprintf("ipc: unknown RPC method %q", req.Method)
	}

	_ = writeFrame(st, resp)
}

type helperSession struct {
	conn        io.ReadWriteCloser
	sess        *yamux.Session
	cleanup     func()
	cleanupOnce sync.Once
	acceptDone  chan struct{}
	dialWG      sync.WaitGroup

	dialerMu sync.RWMutex
	dialer   sshclient.TunnelDialer
}

func (hs *helperSession) setDialer(d sshclient.TunnelDialer) {
	hs.dialerMu.Lock()
	hs.dialer = d
	hs.dialerMu.Unlock()
}

func (hs *helperSession) getDialer() sshclient.TunnelDialer {
	hs.dialerMu.RLock()
	d := hs.dialer
	hs.dialerMu.RUnlock()
	return d
}

func (hs *helperSession) runCleanup() {
	hs.cleanupOnce.Do(func() {
		if hs.cleanup != nil {
			hs.cleanup()
		}
	})
}

// HelperTUNController implements TUNSessionController for the unprivileged GUI by launching and
// communicating with an elevated --tun-helper process over a multiplexed yamux connection.
type HelperTUNController struct {
	caps          TUNCapsDTO
	launcher      helperLauncher
	localRouteMgr splitroute.RouteManager
	logger        *slog.Logger

	mu        sync.Mutex
	launching chan struct{}
	session   *helperSession
	tunActive bool
}

var _ TUNSessionController = (*HelperTUNController)(nil)

// NewHelperTUNController constructs a HelperTUNController with the provided platform launcher.
func NewHelperTUNController(caps TUNCapsDTO, launcher helperLauncher, logger *slog.Logger) *HelperTUNController {
	return newHelperTUNController(caps, launcher, splitroute.NewManager(), logger)
}

func newHelperTUNController(
	caps TUNCapsDTO,
	launcher helperLauncher,
	localRouteMgr splitroute.RouteManager,
	logger *slog.Logger,
) *HelperTUNController {
	if logger == nil {
		logger = slog.Default()
	}
	return &HelperTUNController{
		caps:          normalizeTUNCaps(caps),
		launcher:      launcher,
		localRouteMgr: localRouteMgr,
		logger:        logger,
	}
}

// Capabilities returns the platform TUN capabilities descriptor.
func (c *HelperTUNController) Capabilities() TUNCapsDTO {
	return c.caps
}

// PrepareSession ensures a helper session is running and captures the pre-tunnel OS network snapshot.
func (c *HelperTUNController) PrepareSession(ctx context.Context) (splitroute.NetworkSnapshot, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return splitroute.NetworkSnapshot{}, err
	}

	hs, created, err := c.ensureSession(ctx)
	if err != nil {
		return splitroute.NetworkSnapshot{}, err
	}

	resp, err := callHelperRPC(ctx, hs.sess, rpcRequest{Method: rpcMethodPrepareSnapshot})
	if err != nil {
		if created {
			c.closeSession(hs)
		}
		return splitroute.NetworkSnapshot{}, err
	}
	if resp.Snapshot == nil {
		if created {
			c.closeSession(hs)
		}
		return splitroute.NetworkSnapshot{}, errors.New("ipc: prepare_snapshot returned empty snapshot")
	}
	return *resp.Snapshot, nil
}

// StartTUN starts the elevated TUN session and proxies outbound helper dials through dialer.
func (c *HelperTUNController) StartTUN(ctx context.Context, req TUNStartRequest, dialer sshclient.TunnelDialer) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if dialer == nil {
		return errors.New("tun controller: TunnelDialer must not be nil")
	}

	hs, _, err := c.ensureSession(ctx)
	if err != nil {
		return err
	}
	hs.setDialer(dialer)

	if _, err := callHelperRPC(ctx, hs.sess, rpcRequest{
		Method: rpcMethodStartTUN,
		Start:  &req,
	}); err != nil {
		hs.setDialer(nil)
		c.closeSession(hs)
		var rpcErr *helperRPCError
		if errors.As(err, &rpcErr) {
			return err
		}
		checkCtx, checkCancel := context.WithTimeout(context.Background(), 3*time.Second)
		active, activeErr := c.checkLocalTUNActive(checkCtx)
		checkCancel()
		if activeErr == nil && !active {
			return err
		}
		return fmt.Errorf("%w: %w", err, ErrTUNRollbackIncomplete)
	}

	c.mu.Lock()
	if c.session == hs {
		c.tunActive = true
	}
	c.mu.Unlock()
	return nil
}

// SetBypass toggles Iran/LAN bypass routes and DNS rules in the active helper session.
func (c *HelperTUNController) SetBypass(ctx context.Context, bypassIranLAN bool) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	hs := c.session
	active := c.tunActive
	c.mu.Unlock()
	if hs == nil || !active || hs.sess.IsClosed() {
		return errors.New("tun controller: helper session is not active")
	}

	_, err := callHelperRPC(ctx, hs.sess, rpcRequest{
		Method:        rpcMethodSetBypass,
		BypassIranLAN: &bypassIranLAN,
	})
	return err
}

// Stop idempotently stops the active TUN session in the helper and closes the helper connection.
func (c *HelperTUNController) Stop(ctx context.Context) error {
	ctx = normalizeContext(ctx)

	for {
		c.mu.Lock()
		if ch := c.launching; ch != nil {
			c.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		hs := c.session
		c.session = nil
		c.tunActive = false
		c.mu.Unlock()

		if hs == nil {
			return nil
		}

		var stopErr error
		if !hs.sess.IsClosed() {
			stopCtx := ctx
			var cancel context.CancelFunc
			if _, hasDeadline := ctx.Deadline(); !hasDeadline {
				stopCtx, cancel = context.WithTimeout(ctx, rpcStopTimeout)
			}
			_, stopErr = callHelperRPC(stopCtx, hs.sess, rpcRequest{Method: rpcMethodStop})
			if cancel != nil {
				cancel()
			}
		}

		hs.setDialer(nil)
		_ = hs.sess.Close()
		_ = hs.conn.Close()
		<-hs.acceptDone
		hs.dialWG.Wait()
		hs.runCleanup()

		return stopErr
	}
}

// Stats queries live TUN runner telemetry from the active helper session.
func (c *HelperTUNController) Stats() tun.Stats {
	c.mu.Lock()
	hs := c.session
	active := c.tunActive
	c.mu.Unlock()
	if hs == nil || !active || hs.sess.IsClosed() {
		return tun.Stats{}
	}

	ctx, cancel := context.WithTimeout(context.Background(), rpcStatsTimeout)
	defer cancel()
	resp, err := callHelperRPC(ctx, hs.sess, rpcRequest{Method: rpcMethodStats})
	if err != nil || resp.Stats == nil {
		return tun.Stats{}
	}
	return *resp.Stats
}

func (c *HelperTUNController) checkLocalTUNActive(ctx context.Context) (bool, error) {
	if c.localRouteMgr == nil {
		return false, errors.New("tun controller: local route manager unavailable")
	}
	return c.localRouteMgr.IsTUNStateActive(ctx)
}

// IsActiveOnOS checks TUN presence locally without elevation first, falling back to the helper only
// if the local check fails.
func (c *HelperTUNController) IsActiveOnOS(ctx context.Context) (bool, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if active, err := c.checkLocalTUNActive(ctx); err == nil {
		return active, nil
	}

	c.mu.Lock()
	hs := c.session
	c.mu.Unlock()
	if hs != nil && !hs.sess.IsClosed() {
		resp, err := callHelperRPC(ctx, hs.sess, rpcRequest{Method: rpcMethodCheckActive})
		if err != nil {
			return false, err
		}
		if resp.Active == nil {
			return false, errors.New("ipc: check_active returned nil state")
		}
		return *resp.Active, nil
	}

	var active bool
	if err := c.runOneShotRPC(ctx, rpcRequest{Method: rpcMethodCheckActive}, func(resp rpcResponse) error {
		if resp.Active == nil {
			return errors.New("ipc: check_active returned nil state")
		}
		active = *resp.Active
		return nil
	}); err != nil {
		return false, err
	}
	return active, nil
}

// RestoreFromSnapshot stops an active session if present, or launches a one-shot helper session to
// execute RestoreNetwork and exits cleanly.
func (c *HelperTUNController) RestoreFromSnapshot(ctx context.Context, snap splitroute.NetworkSnapshot) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	hs := c.session
	active := c.tunActive
	c.mu.Unlock()

	if hs != nil && !hs.sess.IsClosed() {
		if active {
			return c.Stop(ctx)
		}
		_, err := callHelperRPC(ctx, hs.sess, rpcRequest{
			Method:   rpcMethodRestoreSnapshot,
			Snapshot: &snap,
		})
		c.closeSession(hs)
		return err
	}

	return c.runOneShotRPC(ctx, rpcRequest{
		Method:   rpcMethodRestoreSnapshot,
		Snapshot: &snap,
	}, nil)
}

func (c *HelperTUNController) ensureSession(ctx context.Context) (*helperSession, bool, error) {
	for {
		c.mu.Lock()
		if c.session != nil && !c.session.sess.IsClosed() {
			hs := c.session
			c.mu.Unlock()
			return hs, false, nil
		}
		if ch := c.launching; ch != nil {
			c.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				return nil, false, ctx.Err()
			}
		}
		if c.launcher == nil {
			c.mu.Unlock()
			return nil, false, errors.New("tun controller: helper launcher must not be nil")
		}
		ch := make(chan struct{})
		c.launching = ch
		c.mu.Unlock()

		conn, cleanup, launchErr := c.launcher.Launch(ctx)
		if launchErr != nil {
			c.finishLaunch(ch, nil)
			return nil, false, fmt.Errorf("tun controller: launch elevated helper: %w", launchErr)
		}

		sess, muxErr := yamux.Client(conn, newYamuxConfig(c.logger))
		if muxErr != nil {
			_ = conn.Close()
			if cleanup != nil {
				cleanup()
			}
			c.finishLaunch(ch, nil)
			return nil, false, fmt.Errorf("tun controller: create yamux client: %w", muxErr)
		}

		hs := &helperSession{
			conn:       conn,
			sess:       sess,
			cleanup:    cleanup,
			acceptDone: make(chan struct{}),
		}
		go c.acceptDialStreams(hs)

		c.finishLaunch(ch, hs)
		return hs, true, nil
	}
}

func (c *HelperTUNController) finishLaunch(ch chan struct{}, hs *helperSession) {
	c.mu.Lock()
	if hs != nil {
		c.session = hs
		c.tunActive = false
	}
	c.launching = nil
	close(ch)
	c.mu.Unlock()
}

func (c *HelperTUNController) closeSession(hs *helperSession) {
	if hs == nil {
		return
	}
	c.mu.Lock()
	if c.session == hs {
		c.session = nil
		c.tunActive = false
	}
	c.mu.Unlock()

	hs.setDialer(nil)
	_ = hs.sess.Close()
	_ = hs.conn.Close()
	<-hs.acceptDone
	hs.dialWG.Wait()
	hs.runCleanup()
}

func (c *HelperTUNController) acceptDialStreams(hs *helperSession) {
	defer close(hs.acceptDone)

	for {
		stream, err := hs.sess.AcceptStream()
		if err != nil {
			break
		}
		hs.dialWG.Add(1)
		go func(st *yamux.Stream) {
			defer hs.dialWG.Done()
			c.handleDialStream(hs, st)
		}(stream)
	}

	c.mu.Lock()
	wasCurrent := c.session == hs
	if wasCurrent {
		c.session = nil
		c.tunActive = false
	}
	c.mu.Unlock()

	if wasCurrent {
		_ = hs.sess.Close()
		_ = hs.conn.Close()
		hs.dialWG.Wait()
		hs.runCleanup()
	}
}

func (c *HelperTUNController) handleDialStream(hs *helperSession, st *yamux.Stream) {
	_ = st.SetReadDeadline(time.Now().Add(dialHandshakeTimeout))
	var req dialReq
	if err := readFrame(st, &req); err != nil {
		_ = st.SetReadDeadline(time.Unix(1, 0))
		_ = st.Close()
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	dialer := hs.getDialer()
	if dialer == nil {
		_ = writeFrame(st, dialResp{Error: "tunnel dialer is not active"})
		_ = st.SetReadDeadline(time.Unix(1, 0))
		_ = st.Close()
		return
	}
	if strings.TrimSpace(req.Network) == "" || strings.TrimSpace(req.Address) == "" {
		_ = writeFrame(st, dialResp{Error: "invalid dial request"})
		_ = st.SetReadDeadline(time.Unix(1, 0))
		_ = st.Close()
		return
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), rpcDialTimeout)
	stopWatch := context.AfterFunc(dialCtx, func() {})
	sessWatchDone := make(chan struct{})
	go func() {
		select {
		case <-hs.sess.CloseChan():
			dialCancel()
		case <-sessWatchDone:
		}
	}()

	targetConn, err := dialer.DialContext(dialCtx, req.Network, req.Address)
	close(sessWatchDone)
	_ = stopWatch()
	dialCancel()

	if err != nil {
		_ = writeFrame(st, dialResp{Error: err.Error()})
		_ = st.SetReadDeadline(time.Unix(1, 0))
		_ = st.Close()
		return
	}

	if err := writeFrame(st, dialResp{OK: true}); err != nil {
		_ = targetConn.Close()
		_ = st.SetReadDeadline(time.Unix(1, 0))
		_ = st.Close()
		return
	}

	proxyStreamAndConn(st, targetConn, hs.sess.CloseChan())
}

func proxyStreamAndConn(st *yamux.Stream, target net.Conn, sessClose <-chan struct{}) {
	done := make(chan struct{})
	go func() {
		select {
		case <-sessClose:
			_ = target.Close()
			_ = st.SetReadDeadline(time.Unix(1, 0))
			_ = st.Close()
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(target, st)
		if err != nil {
			_ = target.Close()
			return
		}
		closeWriteConn(target)
	}()

	_, err := io.Copy(st, target)
	if err != nil {
		_ = st.SetReadDeadline(time.Unix(1, 0))
	}
	_ = st.Close()

	wg.Wait()
	close(done)
	_ = target.Close()
}

func closeWriteConn(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err == nil || !errors.Is(err, errors.ErrUnsupported) {
			return
		}
	}
	_ = conn.Close()
}

func (c *HelperTUNController) runOneShotRPC(ctx context.Context, req rpcRequest, handleResp func(rpcResponse) error) error {
	if c.launcher == nil {
		return errors.New("tun controller: helper launcher must not be nil")
	}

	conn, cleanup, err := c.launcher.Launch(ctx)
	if err != nil {
		return fmt.Errorf("tun controller: launch one-shot helper: %w", err)
	}
	defer func() {
		_ = conn.Close()
		if cleanup != nil {
			cleanup()
		}
	}()

	sess, err := yamux.Client(conn, newYamuxConfig(c.logger))
	if err != nil {
		return fmt.Errorf("tun controller: create one-shot yamux client: %w", err)
	}
	defer sess.Close()

	resp, err := callHelperRPC(ctx, sess, req)
	if err != nil {
		return err
	}
	if handleResp != nil {
		return handleResp(resp)
	}
	return nil
}

func callHelperRPC(ctx context.Context, sess *yamux.Session, req rpcRequest) (rpcResponse, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return rpcResponse{}, err
	}
	if sess == nil || sess.IsClosed() {
		return rpcResponse{}, net.ErrClosed
	}

	stream, err := sess.OpenStream()
	if err != nil {
		return rpcResponse{}, fmt.Errorf("ipc: open RPC stream: %w", err)
	}
	defer func() {
		_ = stream.SetReadDeadline(time.Unix(1, 0))
		_ = stream.Close()
	}()

	stopWatch := context.AfterFunc(ctx, func() {
		_ = stream.SetDeadline(time.Unix(1, 0))
		_ = stream.Close()
	})
	defer stopWatch()

	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	if err := writeFrame(stream, req); err != nil {
		if !stopWatch() && ctx.Err() != nil {
			return rpcResponse{}, ctx.Err()
		}
		return rpcResponse{}, fmt.Errorf("ipc: write RPC %q: %w", req.Method, err)
	}

	var resp rpcResponse
	if err := readFrame(stream, &resp); err != nil {
		if !stopWatch() && ctx.Err() != nil {
			return rpcResponse{}, ctx.Err()
		}
		return rpcResponse{}, fmt.Errorf("ipc: read RPC %q response: %w", req.Method, err)
	}

	if !stopWatch() && ctx.Err() != nil {
		return rpcResponse{}, ctx.Err()
	}
	if !resp.OK || resp.Error != "" {
		msg := resp.Error
		if msg == "" {
			msg = fmt.Sprintf("ipc: RPC %q failed", req.Method)
		}
		return rpcResponse{}, &helperRPCError{
			msg:                msg,
			rollbackIncomplete: resp.RollbackIncomplete,
		}
	}
	return resp, nil
}

// RunHelperMode parses restricted elevated helper CLI flags (--socket or --pipe) and runs the
// TUN helper service over the authenticated local IPC channel.
func RunHelperMode(args []string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	var socketPath, pipeName string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--tun-helper":
			continue
		case arg == "--socket":
			if i+1 >= len(args) {
				return errors.New("tun helper: --socket requires a value")
			}
			i++
			if socketPath != "" {
				return errors.New("tun helper: duplicate --socket flag")
			}
			socketPath = args[i]
		case strings.HasPrefix(arg, "--socket="):
			if socketPath != "" {
				return errors.New("tun helper: duplicate --socket flag")
			}
			socketPath = strings.TrimPrefix(arg, "--socket=")
		case arg == "--pipe":
			if i+1 >= len(args) {
				return errors.New("tun helper: --pipe requires a value")
			}
			i++
			if pipeName != "" {
				return errors.New("tun helper: duplicate --pipe flag")
			}
			pipeName = args[i]
		case strings.HasPrefix(arg, "--pipe="):
			if pipeName != "" {
				return errors.New("tun helper: duplicate --pipe flag")
			}
			pipeName = strings.TrimPrefix(arg, "--pipe=")
		default:
			return fmt.Errorf("tun helper: unsupported argument %q", arg)
		}
	}

	if socketPath != "" && pipeName != "" {
		return errors.New("tun helper: specify only one of --socket or --pipe")
	}
	if socketPath == "" && pipeName == "" {
		return errors.New("tun helper: --socket or --pipe is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), helperStopSignals()...)
	defer stop()

	if socketPath != "" {
		return runHelperSocket(ctx, socketPath, logger)
	}
	return runHelperPipe(ctx, pipeName, logger)
}
