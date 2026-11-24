//go:build windows

package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
	"github.com/AlirezaDelkhahi/tunssh/internal/tun"
)

const (
	windowsPipePrefix        = `\\.\pipe\tunssh-`
	windowsPipeBufferSize    = 64 * 1024
	windowsPipeOpenTimeout   = 2 * time.Second
	windowsHelperReapTimeout = 5 * time.Second
	windowsSeeMaskNoClose    = 0x00000040
	windowsSddlAdminAndUser  = "D:P(A;;GA;;;BA)(A;;GA;;;%s)"
)

var (
	modShell32          = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteExW = modShell32.NewProc("ShellExecuteExW")
)

// shellExecuteInfoW mirrors Win32 SHELLEXECUTEINFOW with native pointer alignment.
type shellExecuteInfoW struct {
	cbSize       uint32
	fMask        uint32
	hwnd         windows.Handle
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     windows.Handle
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    windows.Handle
	dwHotKey     uint32
	hMonitor     windows.Handle
	hProcess     windows.Handle
}

// NewPlatformTUNController constructs the Windows TUNSessionController, running DirectTUNController
// in-process when already elevated or HelperTUNController via UAC ShellExecuteExW otherwise.
func NewPlatformTUNController(logger *slog.Logger) TUNSessionController {
	if logger == nil {
		logger = slog.Default()
	}
	if tun.HasEffectiveCAPNetAdmin() {
		caps := TUNCapsDTO{
			Supported:              true,
			RequiresElevation:      false,
			HasPersistentCap:       false,
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
		CanEnablePersistentCap: false,
		IfaceName:              splitroute.TUNIfaceName,
		TUNIPv4:                splitroute.TUNIPv4Addr,
		TUNDNS:                 splitroute.TUNDNSServer,
	}
	return NewHelperTUNController(caps, &windowsHelperLauncher{logger: logger}, logger)
}

// EnablePersistentTUNAccess is not applicable on Windows because elevation is per-session via UAC.
func EnablePersistentTUNAccess(_ context.Context) error {
	return errors.New("tun access: persistent capability mode is not supported on Windows; UAC elevation is used per session")
}

type windowsHelperLauncher struct {
	logger *slog.Logger
}

func (l *windowsHelperLauncher) Launch(ctx context.Context) (io.ReadWriteCloser, func(), error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	sd, err := buildWindowsHelperPipeSD()
	if err != nil {
		return nil, nil, err
	}
	sa := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
		InheritHandle:      0,
	}

	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, nil, fmt.Errorf("windows helper: generate pipe name: %w", err)
	}
	pipeName := windowsPipePrefix + hex.EncodeToString(rnd[:])
	pipePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, nil, fmt.Errorf("windows helper: encode pipe name: %w", err)
	}

	pipeHandle, err := windows.CreateNamedPipe(
		pipePtr,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE|windows.FILE_FLAG_OVERLAPPED,
		windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS,
		1,
		windowsPipeBufferSize,
		windowsPipeBufferSize,
		0,
		sa,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("windows helper: CreateNamedPipe %q: %w", pipeName, err)
	}

	exePath, err := resolveSelfExecutable()
	if err != nil {
		_ = windows.CloseHandle(pipeHandle)
		return nil, nil, fmt.Errorf("windows helper: resolve executable: %w", err)
	}

	params := "--tun-helper --pipe " + pipeName
	hProcess, err := shellExecuteRunAs(exePath, params, filepath.Dir(exePath))
	if err != nil {
		_ = windows.CloseHandle(pipeHandle)
		return nil, nil, fmt.Errorf("windows helper: UAC launch failed: %w", err)
	}

	helperPID, err := windows.GetProcessId(hProcess)
	if err != nil || helperPID == 0 {
		_ = windows.CloseHandle(hProcess)
		_ = windows.CloseHandle(pipeHandle)
		return nil, nil, fmt.Errorf("windows helper: get helper PID: %w", err)
	}

	if err := waitForNamedPipeClient(ctx, pipeHandle, hProcess); err != nil {
		_ = windows.CloseHandle(hProcess)
		_ = windows.CloseHandle(pipeHandle)
		return nil, nil, err
	}

	var clientPID uint32
	if err := windows.GetNamedPipeClientProcessId(pipeHandle, &clientPID); err != nil {
		_ = windows.CloseHandle(hProcess)
		_ = windows.CloseHandle(pipeHandle)
		return nil, nil, fmt.Errorf("windows helper: verify pipe client PID: %w", err)
	}
	if clientPID != helperPID {
		_ = windows.CloseHandle(hProcess)
		_ = windows.CloseHandle(pipeHandle)
		return nil, nil, fmt.Errorf("windows helper: unauthorized pipe client PID %d (expected %d)", clientPID, helperPID)
	}

	conn, err := newOverlappedPipeConn(pipeHandle)
	if err != nil {
		_ = windows.CloseHandle(hProcess)
		_ = windows.CloseHandle(pipeHandle)
		return nil, nil, err
	}

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			_ = conn.Close()
			_, _ = windows.WaitForSingleObject(hProcess, uint32(windowsHelperReapTimeout/time.Millisecond))
			_ = windows.CloseHandle(hProcess)
		})
	}
	return conn, cleanup, nil
}

func buildWindowsHelperPipeSD() (*windows.SECURITY_DESCRIPTOR, error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("windows helper: read current token user: %w", err)
	}
	if tu == nil || tu.User.Sid == nil {
		return nil, errors.New("windows helper: current token user SID is nil")
	}
	sddl := fmt.Sprintf(windowsSddlAdminAndUser, tu.User.Sid.String())
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("windows helper: build pipe SDDL %q: %w", sddl, err)
	}
	return sd, nil
}

func shellExecuteRunAs(file, params, dir string) (windows.Handle, error) {
	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return 0, err
	}
	filePtr, err := windows.UTF16PtrFromString(file)
	if err != nil {
		return 0, err
	}
	paramsPtr, err := windows.UTF16PtrFromString(params)
	if err != nil {
		return 0, err
	}
	dirPtr, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}

	sei := shellExecuteInfoW{
		cbSize:       uint32(unsafe.Sizeof(shellExecuteInfoW{})),
		fMask:        windowsSeeMaskNoClose,
		lpVerb:       verbPtr,
		lpFile:       filePtr,
		lpParameters: paramsPtr,
		lpDirectory:  dirPtr,
		nShow:        windows.SW_HIDE,
	}

	r1, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	runtime.KeepAlive(verbPtr)
	runtime.KeepAlive(filePtr)
	runtime.KeepAlive(paramsPtr)
	runtime.KeepAlive(dirPtr)
	runtime.KeepAlive(&sei)

	if r1 == 0 {
		if callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
			return 0, callErr
		}
		return 0, errors.New("ShellExecuteExW returned FALSE")
	}
	if sei.hProcess == 0 || sei.hProcess == windows.InvalidHandle {
		return 0, errors.New("ShellExecuteExW succeeded without process handle")
	}
	return sei.hProcess, nil
}

func waitForNamedPipeClient(ctx context.Context, pipeHandle, hProcess windows.Handle) error {
	connectEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("windows helper: create connect event: %w", err)
	}
	defer windows.CloseHandle(connectEv)

	cancelEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("windows helper: create cancel event: %w", err)
	}
	defer windows.CloseHandle(cancelEv)

	stopCancel := context.AfterFunc(ctx, func() {
		_ = windows.SetEvent(cancelEv)
	})
	defer stopCancel()

	var ov windows.Overlapped
	ov.HEvent = connectEv

	connErr := windows.ConnectNamedPipe(pipeHandle, &ov)
	switch {
	case connErr == nil || errors.Is(connErr, windows.ERROR_PIPE_CONNECTED):
		return nil
	case !errors.Is(connErr, windows.ERROR_IO_PENDING):
		return fmt.Errorf("windows helper: ConnectNamedPipe: %w", connErr)
	}

	handles := []windows.Handle{connectEv, hProcess, cancelEv}
	waitRes, waitErr := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
	switch waitRes {
	case windows.WAIT_OBJECT_0:
		var transferred uint32
		if err := windows.GetOverlappedResult(pipeHandle, &ov, &transferred, false); err != nil {
			return fmt.Errorf("windows helper: overlapped ConnectNamedPipe result: %w", err)
		}
		return nil
	case windows.WAIT_OBJECT_0 + 1:
		_ = windows.CancelIoEx(pipeHandle, &ov)
		var dummy uint32
		_ = windows.GetOverlappedResult(pipeHandle, &ov, &dummy, true)
		return errors.New("windows helper: elevated process exited before connecting to pipe")
	case windows.WAIT_OBJECT_0 + 2:
		_ = windows.CancelIoEx(pipeHandle, &ov)
		var dummy uint32
		_ = windows.GetOverlappedResult(pipeHandle, &ov, &dummy, true)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return context.Canceled
	default:
		_ = windows.CancelIoEx(pipeHandle, &ov)
		var dummy uint32
		_ = windows.GetOverlappedResult(pipeHandle, &ov, &dummy, true)
		if waitErr != nil {
			return fmt.Errorf("windows helper: WaitForMultipleObjects: %w", waitErr)
		}
		return fmt.Errorf("windows helper: WaitForMultipleObjects unexpected status 0x%x", waitRes)
	}
}

// RunHelperWindows validates pipeName, opens the GUI-owned Named Pipe with FILE_FLAG_OVERLAPPED,
// and serves TUN helper RPCs until the session closes or ctx is canceled.
func RunHelperWindows(ctx context.Context, pipeName string, logger *slog.Logger) error {
	ctx = normalizeContext(ctx)
	if logger == nil {
		logger = slog.Default()
	}

	cleanPipe, err := validateWindowsPipeName(pipeName)
	if err != nil {
		return err
	}

	pipePtr, err := windows.UTF16PtrFromString(cleanPipe)
	if err != nil {
		return fmt.Errorf("windows helper: encode pipe name: %w", err)
	}

	deadline := time.Now().Add(windowsPipeOpenTimeout)
	var handle windows.Handle
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		handle, err = windows.CreateFile(
			pipePtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			0,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OVERLAPPED,
			0,
		)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			return fmt.Errorf("windows helper: open named pipe %q: %w", cleanPipe, err)
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	conn, err := newOverlappedPipeConn(handle)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return err
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

func runHelperSocket(_ context.Context, _ string, _ *slog.Logger) error {
	return errors.New("tun helper: --socket is only supported on Linux")
}

func runHelperPipe(ctx context.Context, pipeName string, logger *slog.Logger) error {
	return RunHelperWindows(ctx, pipeName, logger)
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

func validateWindowsPipeName(pipeName string) (string, error) {
	trimmed := strings.TrimSpace(pipeName)
	if !strings.HasPrefix(trimmed, windowsPipePrefix) {
		return "", fmt.Errorf("windows helper: invalid pipe name %q", pipeName)
	}
	suffix := strings.TrimPrefix(trimmed, windowsPipePrefix)
	if suffix == "" || strings.ContainsAny(suffix, `/\:*?"<>| `+"\t\r\n") {
		return "", fmt.Errorf("windows helper: unsafe pipe suffix in %q", pipeName)
	}
	return trimmed, nil
}

// overlappedPipeConn wraps a Windows Named Pipe handle opened with FILE_FLAG_OVERLAPPED using
// independent per-direction events and mutexes so concurrent yamux Read and Write never deadlock.
type overlappedPipeConn struct {
	handle     windows.Handle
	readEvent  windows.Handle
	writeEvent windows.Handle
	closeEvent windows.Handle

	readMu  sync.Mutex
	writeMu sync.Mutex

	closeMu   sync.RWMutex
	closed    bool
	activeOps sync.WaitGroup
	closeOnce sync.Once

	readDeadlineNano  atomic.Int64
	writeDeadlineNano atomic.Int64
}

func newOverlappedPipeConn(handle windows.Handle) (*overlappedPipeConn, error) {
	readEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, fmt.Errorf("windows pipe: create read event: %w", err)
	}
	writeEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(readEv)
		return nil, fmt.Errorf("windows pipe: create write event: %w", err)
	}
	closeEv, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(readEv)
		_ = windows.CloseHandle(writeEv)
		return nil, fmt.Errorf("windows pipe: create close event: %w", err)
	}
	return &overlappedPipeConn{
		handle:     handle,
		readEvent:  readEv,
		writeEvent: writeEv,
		closeEvent: closeEv,
	}, nil
}

func (c *overlappedPipeConn) acquireOp() bool {
	c.closeMu.RLock()
	if c.closed {
		c.closeMu.RUnlock()
		return false
	}
	c.activeOps.Add(1)
	c.closeMu.RUnlock()
	return true
}

func (c *overlappedPipeConn) releaseOp() {
	c.activeOps.Done()
}

func (c *overlappedPipeConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.acquireOp() {
		return 0, net.ErrClosed
	}
	defer c.releaseOp()

	c.readMu.Lock()
	defer c.readMu.Unlock()

	if err := windows.ResetEvent(c.readEvent); err != nil {
		return 0, err
	}
	ov := windows.Overlapped{HEvent: c.readEvent}
	var done uint32

	err := windows.ReadFile(c.handle, p, &done, &ov)
	if err == nil {
		if done == 0 {
			return 0, io.EOF
		}
		return int(done), nil
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, mapWindowsPipeReadErr(err)
	}

	waitMs := deadlineToWaitMs(c.readDeadlineNano.Load())
	handles := []windows.Handle{c.readEvent, c.closeEvent}
	waitRes, waitErr := windows.WaitForMultipleObjects(handles, false, waitMs)
	switch waitRes {
	case windows.WAIT_OBJECT_0:
		if ovErr := windows.GetOverlappedResult(c.handle, &ov, &done, false); ovErr != nil {
			return int(done), mapWindowsPipeReadErr(ovErr)
		}
		if done == 0 {
			return 0, io.EOF
		}
		return int(done), nil
	case windows.WAIT_OBJECT_0 + 1:
		_ = windows.CancelIoEx(c.handle, &ov)
		_ = windows.GetOverlappedResult(c.handle, &ov, &done, true)
		return 0, net.ErrClosed
	case uint32(windows.WAIT_TIMEOUT):
		_ = windows.CancelIoEx(c.handle, &ov)
		if ovErr := windows.GetOverlappedResult(c.handle, &ov, &done, true); ovErr == nil && done > 0 {
			return int(done), nil
		}
		return 0, os.ErrDeadlineExceeded
	default:
		_ = windows.CancelIoEx(c.handle, &ov)
		_ = windows.GetOverlappedResult(c.handle, &ov, &done, true)
		if waitErr != nil {
			return 0, waitErr
		}
		return 0, fmt.Errorf("windows pipe read wait failed: 0x%x", waitRes)
	}
}

func (c *overlappedPipeConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.acquireOp() {
		return 0, net.ErrClosed
	}
	defer c.releaseOp()

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for total < len(p) {
		c.closeMu.RLock()
		closed := c.closed
		c.closeMu.RUnlock()
		if closed {
			return total, net.ErrClosed
		}
		if err := windows.ResetEvent(c.writeEvent); err != nil {
			return total, err
		}
		ov := windows.Overlapped{HEvent: c.writeEvent}
		var done uint32

		chunk := p[total:]
		err := windows.WriteFile(c.handle, chunk, &done, &ov)
		if err == nil {
			if done == 0 {
				return total, io.ErrShortWrite
			}
			total += int(done)
			continue
		}
		if !errors.Is(err, windows.ERROR_IO_PENDING) {
			return total, mapWindowsPipeWriteErr(err)
		}

		waitMs := deadlineToWaitMs(c.writeDeadlineNano.Load())
		handles := []windows.Handle{c.writeEvent, c.closeEvent}
		waitRes, waitErr := windows.WaitForMultipleObjects(handles, false, waitMs)
		switch waitRes {
		case windows.WAIT_OBJECT_0:
			if ovErr := windows.GetOverlappedResult(c.handle, &ov, &done, false); ovErr != nil {
				return total, mapWindowsPipeWriteErr(ovErr)
			}
			if done == 0 {
				return total, io.ErrShortWrite
			}
			total += int(done)
		case windows.WAIT_OBJECT_0 + 1:
			_ = windows.CancelIoEx(c.handle, &ov)
			_ = windows.GetOverlappedResult(c.handle, &ov, &done, true)
			return total, net.ErrClosed
		case uint32(windows.WAIT_TIMEOUT):
			_ = windows.CancelIoEx(c.handle, &ov)
			if ovErr := windows.GetOverlappedResult(c.handle, &ov, &done, true); ovErr == nil && done > 0 {
				total += int(done)
				if total == len(p) {
					return total, nil
				}
			}
			return total, os.ErrDeadlineExceeded
		default:
			_ = windows.CancelIoEx(c.handle, &ov)
			_ = windows.GetOverlappedResult(c.handle, &ov, &done, true)
			if waitErr != nil {
				return total, waitErr
			}
			return total, fmt.Errorf("windows pipe write wait failed: 0x%x", waitRes)
		}
	}
	return total, nil
}

func (c *overlappedPipeConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *overlappedPipeConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readDeadlineNano.Store(0)
	} else {
		c.readDeadlineNano.Store(t.UnixNano())
	}
	return nil
}

func (c *overlappedPipeConn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		c.writeDeadlineNano.Store(0)
	} else {
		c.writeDeadlineNano.Store(t.UnixNano())
	}
	return nil
}

func (c *overlappedPipeConn) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		c.closeMu.Lock()
		c.closed = true
		_ = windows.SetEvent(c.closeEvent)
		_ = windows.CancelIoEx(c.handle, nil)
		c.closeMu.Unlock()

		c.activeOps.Wait()

		closeErr = windows.CloseHandle(c.handle)
		_ = windows.CloseHandle(c.readEvent)
		_ = windows.CloseHandle(c.writeEvent)
		_ = windows.CloseHandle(c.closeEvent)
	})
	return closeErr
}

func deadlineToWaitMs(deadlineNano int64) uint32 {
	if deadlineNano == 0 {
		return windows.INFINITE
	}
	rem := time.Until(time.Unix(0, deadlineNano))
	if rem <= 0 {
		return 0
	}
	ms := rem.Milliseconds()
	if ms > int64(windows.INFINITE-1) {
		return windows.INFINITE - 1
	}
	return uint32(ms)
}

func mapWindowsPipeReadErr(err error) error {
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) ||
		errors.Is(err, windows.ERROR_NO_DATA) {
		return io.EOF
	}
	if errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		return net.ErrClosed
	}
	return err
}

func mapWindowsPipeWriteErr(err error) error {
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) ||
		errors.Is(err, windows.ERROR_PIPE_NOT_CONNECTED) ||
		errors.Is(err, windows.ERROR_NO_DATA) {
		return io.ErrClosedPipe
	}
	if errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		return net.ErrClosed
	}
	return err
}

func testCheckLinuxPeerCred(_ uint32, _ bool) error {
	return errors.ErrUnsupported
}

func testAcceptUnixPeerCred(_ context.Context, _ *net.UnixListener, _ bool, _ uint32) (net.Conn, uint32, error) {
	return nil, 0, errors.ErrUnsupported
}
