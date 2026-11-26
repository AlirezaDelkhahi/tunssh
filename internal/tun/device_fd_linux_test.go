//go:build linux

package tun

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func assertFDClosed(t *testing.T, fd int) {
	t.Helper()
	_, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("expected fd %d to be closed (EBADF), got err=%v", fd, err)
	}
}

func TestNewFDRunner_StartStopClosesFD(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	defer func() {
		_ = unix.Close(fds[1])
		// Ensure fds[0] is cleaned up if the test aborts early.
		if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			_ = unix.Close(fds[0])
		}
	}()

	runner := NewFDRunner(fds[0])
	cfg := Config{
		IfaceName:    "tun0",
		MTU:          DefaultMTU,
		IPv4CIDR:     DefaultIPv4CIDR,
		IPv6CIDR:     DefaultIPv6CIDR,
		EnableIPv6:   true,
		TunnelDialer: &mockDialer{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := runner.Start(ctx, cfg); err != nil {
		t.Fatalf("NewFDRunner.Start failed: %v", err)
	}

	st := runner.Stats()
	if !st.Running {
		t.Fatalf("expected Stats().Running == true after Start, got %+v", st)
	}
	if st.IfaceName != "tun0" {
		t.Fatalf("expected Stats().IfaceName == %q, got %q", "tun0", st.IfaceName)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()

	if err := runner.Stop(stopCtx); err != nil {
		t.Fatalf("Runner.Stop failed: %v", err)
	}
	if err := runner.Stop(stopCtx); err != nil {
		t.Fatalf("idempotent Runner.Stop failed: %v", err)
	}

	stAfter := runner.Stats()
	if stAfter.Running {
		t.Fatalf("expected Stats().Running == false after Stop, got %+v", stAfter)
	}

	assertFDClosed(t, fds[0])
}

func TestNewFDRunner_EarlyFailureClosesFD(t *testing.T) {
	t.Run("nil TunnelDialer", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
		if err != nil {
			t.Fatalf("Socketpair failed: %v", err)
		}
		defer func() {
			_ = unix.Close(fds[1])
			if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				_ = unix.Close(fds[0])
			}
		}()

		runner := NewFDRunner(fds[0])
		_, err = runner.Start(context.Background(), Config{
			IfaceName: "tun0",
			MTU:       DefaultMTU,
			IPv4CIDR:  DefaultIPv4CIDR,
		})
		if err == nil {
			t.Fatal("expected Start with nil TunnelDialer to fail")
		}
		assertFDClosed(t, fds[0])
	})

	t.Run("already canceled context", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
		if err != nil {
			t.Fatalf("Socketpair failed: %v", err)
		}
		defer func() {
			_ = unix.Close(fds[1])
			if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				_ = unix.Close(fds[0])
			}
		}()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		runner := NewFDRunner(fds[0])
		_, err = runner.Start(ctx, Config{
			IfaceName:    "tun0",
			MTU:          DefaultMTU,
			IPv4CIDR:     DefaultIPv4CIDR,
			TunnelDialer: &mockDialer{},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		assertFDClosed(t, fds[0])
	})

	t.Run("invalid DNSUDPAddr", func(t *testing.T) {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
		if err != nil {
			t.Fatalf("Socketpair failed: %v", err)
		}
		defer func() {
			_ = unix.Close(fds[1])
			if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
				_ = unix.Close(fds[0])
			}
		}()

		runner := NewFDRunner(fds[0])
		_, err = runner.Start(context.Background(), Config{
			IfaceName:    "tun0",
			MTU:          DefaultMTU,
			IPv4CIDR:     DefaultIPv4CIDR,
			TunnelDialer: &mockDialer{},
			DNSUDPAddr:   "not-a-valid-addr",
		})
		if err == nil {
			t.Fatal("expected Start with invalid DNSUDPAddr to fail")
		}
		assertFDClosed(t, fds[0])
	})
}

func TestNewFDRunner_NegativeFDReturnsError(t *testing.T) {
	runner := NewFDRunner(-1)
	_, err := runner.Start(context.Background(), Config{
		IfaceName:    "tun0",
		MTU:          DefaultMTU,
		IPv4CIDR:     DefaultIPv4CIDR,
		TunnelDialer: &mockDialer{},
	})
	if err == nil {
		t.Fatal("expected NewFDRunner(-1).Start to return an error")
	}

	// Also verify already-active runner does not panic on duplicate Start.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	defer func() {
		_ = unix.Close(fds[1])
		if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			_ = unix.Close(fds[0])
		}
	}()
	r2 := NewFDRunner(fds[0])
	cfg := Config{
		IfaceName: "tun0",
		MTU:       DefaultMTU,
		IPv4CIDR:  DefaultIPv4CIDR,
		TunnelDialer: &mockDialer{
			fn: func(ctx context.Context, network, address string) (net.Conn, error) {
				return nil, errors.New("unused")
			},
		},
	}
	if _, err := r2.Start(context.Background(), cfg); err != nil {
		t.Fatalf("r2.Start failed: %v", err)
	}
	if _, err := r2.Start(context.Background(), cfg); err == nil {
		t.Fatal("expected duplicate Start on active FDRunner to fail")
	}
	if err := r2.Stop(context.Background()); err != nil {
		t.Fatalf("r2.Stop failed: %v", err)
	}
	assertFDClosed(t, fds[0])
}

func TestNewFDRunner_StopWithoutStartClosesFD(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("Socketpair failed: %v", err)
	}
	defer func() {
		_ = unix.Close(fds[1])
		if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			_ = unix.Close(fds[0])
		}
	}()

	runner := NewFDRunner(fds[0])
	if err := runner.Stop(context.Background()); err != nil {
		t.Fatalf("Stop on unstarted FDRunner failed: %v", err)
	}
	assertFDClosed(t, fds[0])

	// Idempotent second Stop must succeed cleanly.
	if err := runner.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop on unstarted FDRunner failed: %v", err)
	}
}
