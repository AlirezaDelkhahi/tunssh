//go:build linux

package tun

import (
	"fmt"
	"net"
	"sync"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type fdDevice struct {
	stack.LinkEndpoint
	name       string
	closeFD    func()
	beforeOnce sync.Once
	afterOnce  sync.Once
}

var _ postWaitCloser = (*fdDevice)(nil)

func (d *fdDevice) Name() string {
	return d.name
}

func (d *fdDevice) Type() string {
	return "fd"
}

// CloseBeforeWait stops inbound packet dispatch without closing the underlying FD so
// gVisor stack.Close() / stack.Wait() can safely finish any outbound writes first.
func (d *fdDevice) CloseBeforeWait() {
	d.beforeOnce.Do(func() {
		if d.LinkEndpoint != nil {
			d.LinkEndpoint.Attach(nil)
			d.LinkEndpoint.Close()
		}
	})
}

// CloseAfterWait waits for link endpoint goroutines to exit and then closes the FD once.
func (d *fdDevice) CloseAfterWait() {
	d.afterOnce.Do(func() {
		if d.LinkEndpoint != nil {
			d.LinkEndpoint.Wait()
		}
		if d.closeFD != nil {
			d.closeFD()
		}
	})
}

// Close provides full two-phase teardown when fdDevice is closed directly outside Runner.
func (d *fdDevice) Close() {
	d.CloseBeforeWait()
	d.CloseAfterWait()
}

// NewFDRunner constructs a Runner that wraps an already-open TUN file descriptor
// (for example, from Android's VpnService.Builder.establish()). The Runner takes
// ownership of fd and guarantees it is closed at most once on any failure or Stop.
func NewFDRunner(fd int) *Runner {
	var once sync.Once
	closeFD := func() {
		once.Do(func() {
			if fd >= 0 {
				_ = unix.Close(fd)
			}
		})
	}
	return &Runner{
		cleanupUnused: closeFD,
		openDevice: func(name string, mtu int, ipv4CIDR, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error) {
			if fd < 0 {
				return nil, 0, fmt.Errorf("tun: invalid file descriptor %d", fd)
			}
			return openFDDevice(name, mtu, ipv4CIDR, ipv6CIDR, enableIPv6, fd, closeFD)
		},
	}
}

func openFDDevice(name string, mtu int, ipv4CIDR, ipv6CIDR string, enableIPv6 bool, fd int, closeFD func()) (device.Device, int, error) {
	normName, normMTU, _, _, err := normalizeDeviceConfig(name, mtu, ipv4CIDR, ipv6CIDR, enableIPv6)
	if err != nil {
		if closeFD != nil {
			closeFD()
		}
		return nil, 0, err
	}

	ep, err := fdbased.New(&fdbased.Options{
		FDs:                []int{fd},
		MTU:                uint32(normMTU),
		EthernetHeader:     false,
		PacketDispatchMode: fdbased.Readv,
	})
	if err != nil {
		if closeFD != nil {
			closeFD()
		}
		return nil, 0, fmt.Errorf("tun: create fd-based link endpoint: %w", err)
	}

	ifIndex := 0
	if iface, err := net.InterfaceByName(normName); err == nil && iface != nil {
		ifIndex = iface.Index
	}

	return &fdDevice{
		LinkEndpoint: ep,
		name:         normName,
		closeFD:      closeFD,
	}, ifIndex, nil
}
