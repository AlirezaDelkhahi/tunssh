//go:build android

package splitroute

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
)

// NewManager returns an Android RouteManager stub; Android split routing is configured
// via VpnService.Builder.addRoute() rather than OS netlink mutations.
func NewManager() RouteManager {
	return NewManagerWithDeps(androidUnsupportedOps{}, androidUnsupportedDNS{}, nil)
}

// bindToInterfaceControl returns nil on Android where outbound sockets are protected
// via VpnService.protect(fd) supplied through ConnectConfig.DialControl.
func bindToInterfaceControl(ifaceName string, ifaceIndex int, isIPv6 bool) func(network, address string, c syscall.RawConn) error {
	return nil
}

type androidUnsupportedOps struct{}

var _ RouteOps = androidUnsupportedOps{}

func (androidUnsupportedOps) CaptureDefaultRoute(context.Context) (netip.Addr, netip.Addr, string, int, error) {
	return netip.Addr{}, netip.Addr{}, "", 0, errors.ErrUnsupported
}

func (androidUnsupportedOps) AddRoute(context.Context, RouteSpec) error {
	return errors.ErrUnsupported
}

func (androidUnsupportedOps) DeleteRoute(context.Context, RouteSpec) error {
	return errors.ErrUnsupported
}

func (androidUnsupportedOps) IsTUNRouteOrIfaceActive(context.Context, string) (bool, error) {
	return false, nil
}

type androidUnsupportedDNS struct{}

var _ DNSConfigurator = androidUnsupportedDNS{}

func (androidUnsupportedDNS) CaptureDNS(context.Context, string, int) (string, []netip.Addr, []WinAdapterDNSBackup, []LinuxDNSBackup, string, error) {
	return "", nil, nil, nil, "", errors.ErrUnsupported
}

func (androidUnsupportedDNS) ApplyTUNDNS(context.Context, NetworkSnapshot, netip.Addr) error {
	return errors.ErrUnsupported
}

func (androidUnsupportedDNS) RestoreDNS(context.Context, NetworkSnapshot) error {
	return errors.ErrUnsupported
}
