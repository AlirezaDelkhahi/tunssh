//go:build linux

package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
	"github.com/AlirezaDelkhahi/tunssh/internal/tun"
)

const (
	linuxHelperDirName     = "tunssh"
	linuxSocketPrefix      = "tunssh-"
	linuxSocketSuffix      = ".sock"
	linuxMaxSunPathBytes   = 104
	linuxHelperDialTimeout = 5 * time.Second
	linuxHelperReapTimeout = 5 * time.Second
	linuxStderrCaptureMax  = 4096
)

// NewPlatformTUNController constructs the Linux TUNSessionController, using DirectTUNController
// in-process when CAP_NET_ADMIN is already effective, or HelperTUNController via pkexec otherwise.
func NewPlatformTUNController(logger *slog.Logger) TUNSessionController {
	if logger == nil {
		logger = slog.Default()
	}
	if tun.HasEffectiveCAPNetAdmin() {
		caps := TUNCapsDTO{
			Supported:              true,
			RequiresElevation:      false,
			HasPersistentCap:       true,
			CanEnablePersistentCap: false,
			IfaceName:              splitroute.TUNIfaceName,
			TUNIPv4:                splitroute.TUNIPv4Addr,
			TUNDNS:                 splitroute.TUNDNSServer,
		}
		return NewDirectTUNController(caps, splitroute.NewManager(), nil, nil, logger)
	}

	caps := TUNCapsDTO{
		Supported:              true,
		RequiresElevation:      true,
		HasPersistentCap:       false,
		CanEnablePersistentCap: hasPkexecAndSetcap(),
		IfaceName:              splitroute.TUNIfaceName,
		TUNIPv4:                splitroute.TUNIPv4Addr,
		TUNDNS:                 splitroute.TUNDNSServer,
	}
	return NewHelperTUNController(caps, &linuxHelperLauncher{logger: logger}, logger)
}

func hasPkexecAndSetcap() bool {
	if _, err := exec.LookPath("pkexec"); err != nil {
		return false
	}
	_, ok := findSetcapBinary()
	return ok
}

func findSetcapBinary() (string, bool) {
	if p, err := exec.LookPath("setcap"); err == nil && p != "" {
		return p, true
	}
	for _, candidate := range []string{"/usr/sbin/setcap", "/sbin/setcap"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, true
		}
	}
	return "", false
}

// EnablePersistentTUNAccess grants cap_net_admin and cap_net_bind_service+ep to the current
// executable via pkexec setcap so future runs require no elevation prompts.
func EnablePersistentTUNAccess(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	pkexecPath, err := exec.LookPath("pkexec")
	if err != nil {
		return fmt.Errorf("tun access: pkexec not found: %w", err)
	}
	setcapPath, ok := findSetcapBinary()
	if !ok {
		return errors.New("tun access: setcap binary not found")
	}
	exePath, err := resolveSelfExecutable()
	if err != nil {
		return fmt.Errorf("tun access: resolve executable: %w", err)
	}

	cmd := exec.CommandContext(ctx, pkexecPath, setcapPath, "cap_net_admin,cap_net_bind_service+ep", exePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("tun access: pkexec setcap failed: %w (%s)", err, msg)
		}
		return fmt.Errorf("tun access: pkexec setcap failed: %w", err)
	}
	return nil
}

type linuxHelperLauncher struct {
	logger *slog.Logger
}

func (l *linuxHelperLauncher) Launch(ctx context.Context) (io.ReadWriteCloser, func(), error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	pkexecPath, err := exec.LookPath("pkexec")
	if err != nil {
		return nil, nil, fmt.Errorf("linux helper: pkexec not found: %w", err)
	}
	exePath, err := resolveSelfExecutable()
	if err != nil {
		return nil, nil, fmt.Errorf("linux helper: resolve executable: %w", err)
	}

	sockDir, err := ensureLinuxSocketDir()
	if err != nil {
		return nil, nil, err
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, nil, fmt.Errorf("linux helper: generate socket name: %w", err)
	}
	sockPath := filepath.Join(sockDir, linuxSocketPrefix+hex.EncodeToString(rnd[:])+linuxSocketSuffix)
	if len(sockPath) >= linuxMaxSunPathBytes {
		return nil, nil, fmt.Errorf("linux helper: socket path length %d exceeds limit", len(sockPath))
	}
	_ = os.Remove(sockPath)

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, nil, fmt.Errorf("linux helper: bind unix socket %q: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, nil, fmt.Errorf("linux helper: chmod socket %q: %w", sockPath, err)
	}

	// Do NOT tie cmd lifetime to Launch(ctx): Launch(ctx) bounds only the handshake/auth prompt,
	// whereas the elevated helper stays alive until the IPC connection closes.
	cmd := exec.Command(pkexecPath, exePath, "--tun-helper", "--socket", sockPath)
	stderrBuf := &limitedBuffer{max: linuxStderrCaptureMax}
	cmd.Stderr = stderrBuf
	if err := cmd.Start(); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, nil, fmt.Errorf("linux helper: start pkexec: %w", err)
	}

	cmdDone := make(chan error, 1)
	go func() {
		cmdDone <- cmd.Wait()
	}()

	conn, err := acceptVerifiedUnixConn(ctx, ln, cmdDone, stderrBuf, verifyLinuxPeerCred)
	_ = ln.Close()
	_ = os.Remove(sockPath)
	if err != nil {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
		select {
		case <-cmdDone:
		case <-time.After(linuxHelperReapTimeout):
		}
		return nil, nil, err
	}

	var reapOnce sync.Once
	cleanup := func() {
		reapOnce.Do(func() {
			_ = conn.Close()
			_ = os.Remove(sockPath)
			select {
			case <-cmdDone:
			case <-time.After(linuxHelperReapTimeout):
			}
		})
	}
	return conn, cleanup, nil
}

func acceptVerifiedUnixConn(
	ctx context.Context,
	ln *net.UnixListener,
	cmdDone <-chan error,
	stderrBuf *limitedBuffer,
	verifyCred func(*unix.Ucred) error,
) (*net.UnixConn, error) {
	type acceptResult struct {
		conn *net.UnixConn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.AcceptUnix()
		acceptCh <- acceptResult{conn: c, err: err}
	}()

	var unixConn *net.UnixConn
	select {
	case res := <-acceptCh:
		if res.err != nil {
			return nil, fmt.Errorf("linux helper: accept unix connection: %w", res.err)
		}
		unixConn = res.conn
	case waitErr := <-cmdDone:
		_ = ln.Close()
		if res := <-acceptCh; res.conn != nil {
			_ = res.conn.Close()
		}
		stderrMsg := strings.TrimSpace(stderrBuf.String())
		if stderrMsg != "" {
			return nil, fmt.Errorf("linux helper: pkexec exited before connecting: %v (%s)", waitErr, stderrMsg)
		}
		return nil, fmt.Errorf("linux helper: pkexec exited before connecting: %w", waitErr)
	case <-ctx.Done():
		_ = ln.Close()
		if res := <-acceptCh; res.conn != nil {
			_ = res.conn.Close()
		}
		return nil, ctx.Err()
	}

	ucred, err := extractUnixPeerCred(unixConn)
	if err != nil {
		_ = unixConn.Close()
		return nil, fmt.Errorf("linux helper: inspect SO_PEERCRED: %w", err)
	}
	if err := verifyCred(ucred); err != nil {
		_ = unixConn.Close()
		return nil, err
	}
	return unixConn, nil
}

func extractUnixPeerCred(conn *net.UnixConn) (*unix.Ucred, error) {
	if conn == nil {
		return nil, errors.New("unix connection is nil")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		ucred   *unix.Ucred
		sockErr error
	)
	if ctrlErr := rawConn.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); ctrlErr != nil {
		return nil, ctrlErr
	}
	if sockErr != nil {
		return nil, sockErr
	}
	return ucred, nil
}

// verifyLinuxPeerCred verifies that the connecting Unix socket peer has effective UID 0 (root).
func verifyLinuxPeerCred(ucred *unix.Ucred) error {
	if ucred == nil {
		return errors.New("linux helper: missing SO_PEERCRED credentials")
	}
	if ucred.Uid != 0 {
		return fmt.Errorf("linux helper: unauthorized peer uid %d (expected 0)", ucred.Uid)
	}
	return nil
}

// RunHelperLinux validates socketPath, connects to the unprivileged GUI's Unix Domain Socket,
// and serves TUN helper RPCs until the session closes or ctx is canceled.
func RunHelperLinux(ctx context.Context, socketPath string, logger *slog.Logger) error {
	ctx = normalizeContext(ctx)
	if logger == nil {
		logger = slog.Default()
	}

	cleanPath, err := validateLinuxHelperSocketPath(socketPath)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{Timeout: linuxHelperDialTimeout}
	conn, err := dialer.DialContext(ctx, "unix", cleanPath)
	if err != nil {
		return fmt.Errorf("linux helper: dial unix socket %q: %w", cleanPath, err)
	}

	caps := TUNCapsDTO{
		Supported: true,
		IfaceName: splitroute.TUNIfaceName,
		TUNIPv4:   splitroute.TUNIPv4Addr,
		TUNDNS:    splitroute.TUNDNSServer,
	}
	ctrl := NewDirectTUNController(caps, splitroute.NewManager(), nil, nil, logger)
	return RunHelperOnConn(ctx, conn, ctrl, logger)
}

func runHelperSocket(ctx context.Context, socketPath string, logger *slog.Logger) error {
	return RunHelperLinux(ctx, socketPath, logger)
}

func runHelperPipe(_ context.Context, _ string, _ *slog.Logger) error {
	return errors.New("tun helper: --pipe is only supported on Windows")
}

func helperStopSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func resolveSelfExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err == nil && resolved != "" {
		return resolved, nil
	}
	return exe, nil
}

func ensureLinuxSocketDir() (string, error) {
	candidates := linuxCandidateSocketDirs(false)
	if len(candidates) == 0 {
		return "", errors.New("linux helper: unable to resolve runtime or cache directory for socket")
	}
	dir := candidates[0]
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("linux helper: create socket directory %q: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", fmt.Errorf("linux helper: chmod socket directory %q: %w", dir, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("linux helper: stat socket directory %q: %w", dir, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("linux helper: unsafe socket directory %q", dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(os.Getuid()) {
		return "", fmt.Errorf("linux helper: socket directory %q not owned by current user", dir)
	}
	return dir, nil
}

func linuxCandidateSocketDirs(includePkexec bool) []string {
	var dirs []string
	add := func(base string) {
		base = strings.TrimSpace(base)
		if base == "" || !filepath.IsAbs(base) {
			return
		}
		cand := filepath.Clean(filepath.Join(base, linuxHelperDirName))
		for _, existing := range dirs {
			if existing == cand {
				return
			}
		}
		dirs = append(dirs, cand)
	}

	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		add(xdgRuntime)
	}
	if xdgCache := os.Getenv("XDG_CACHE_HOME"); xdgCache != "" {
		add(xdgCache)
	}
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		add(cacheDir)
	}
	if includePkexec {
		// pkexec clears XDG_RUNTIME_DIR and resets HOME=/root, while preserving PKEXEC_UID.
		if rawUID := strings.TrimSpace(os.Getenv("PKEXEC_UID")); rawUID != "" {
			if _, err := strconv.ParseUint(rawUID, 10, 32); err == nil {
				add(filepath.Join("/run/user", rawUID))
				if u, err := user.LookupId(rawUID); err == nil && u.HomeDir != "" {
					add(filepath.Join(u.HomeDir, ".cache"))
				}
			}
		}
	}
	return dirs
}

func validateLinuxHelperSocketPath(socketPath string) (string, error) {
	trimmed := strings.TrimSpace(socketPath)
	if trimmed == "" {
		return "", errors.New("linux helper: socket path must not be empty")
	}
	if !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("linux helper: socket path %q must be absolute", socketPath)
	}
	cleanPath := filepath.Clean(trimmed)
	if cleanPath != trimmed || strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("linux helper: unsafe socket path %q", socketPath)
	}

	base := filepath.Base(cleanPath)
	if !strings.HasPrefix(base, linuxSocketPrefix) || !strings.HasSuffix(base, linuxSocketSuffix) || len(base) <= len(linuxSocketPrefix)+len(linuxSocketSuffix) {
		return "", fmt.Errorf("linux helper: invalid socket file name %q", base)
	}

	parentDir := filepath.Dir(cleanPath)
	allowed := false
	for _, dir := range linuxCandidateSocketDirs(true) {
		if parentDir == dir {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("linux helper: socket path %q is outside user runtime/cache directory", cleanPath)
	}

	info, err := os.Lstat(cleanPath)
	if err != nil {
		return "", fmt.Errorf("linux helper: stat socket %q: %w", cleanPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return "", fmt.Errorf("linux helper: %q is not a regular unix socket", cleanPath)
	}

	if rawUID := strings.TrimSpace(os.Getenv("PKEXEC_UID")); rawUID != "" {
		if expectedUID, err := strconv.ParseUint(rawUID, 10, 32); err == nil {
			if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != uint32(expectedUID) {
				return "", fmt.Errorf("linux helper: socket %q owned by uid %d, expected %d", cleanPath, st.Uid, expectedUID)
			}
		}
	}
	return cleanPath, nil
}

type limitedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.max > 0 && b.buf.Len() < b.max {
		remain := b.max - b.buf.Len()
		if len(p) > remain {
			b.buf.Write(p[:remain])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testCheckLinuxPeerCred exposes verifyLinuxPeerCred to cross-platform unit tests without
// requiring unix imports in helper_ipc_test.go.
func testCheckLinuxPeerCred(uid uint32, nilCred bool) error {
	if nilCred {
		return verifyLinuxPeerCred(nil)
	}
	return verifyLinuxPeerCred(&unix.Ucred{Pid: 1, Uid: uid, Gid: uid})
}

// testAcceptUnixPeerCred tests real SO_PEERCRED extraction and verification on a Unix listener.
func testAcceptUnixPeerCred(ctx context.Context, ln *net.UnixListener, useDefaultVerify bool, expectUID uint32) (net.Conn, uint32, error) {
	var gotUID uint32
	verifyFn := func(ucred *unix.Ucred) error {
		if ucred != nil {
			gotUID = ucred.Uid
		}
		if useDefaultVerify {
			return verifyLinuxPeerCred(ucred)
		}
		if ucred == nil {
			return errors.New("missing ucred")
		}
		if ucred.Uid != expectUID {
			return fmt.Errorf("unexpected uid %d want %d", ucred.Uid, expectUID)
		}
		return nil
	}
	conn, err := acceptVerifiedUnixConn(ctx, ln, make(chan error), &limitedBuffer{max: 256}, verifyFn)
	if err != nil {
		return nil, gotUID, err
	}
	return conn, gotUID, nil
}
