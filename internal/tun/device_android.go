//go:build android

package tun

import (
	"errors"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
)

// HasEffectiveCAPNetAdmin reports false on Android where TUN creation is delegated
// to VpnService.Builder.establish().
func HasEffectiveCAPNetAdmin() bool {
	return false
}

// OpenAndConfigureDevice is unsupported on Android; use NewFDRunner with the
// ParcelFileDescriptor obtained from VpnService.Builder.establish().
func OpenAndConfigureDevice(name string, mtu int, ipv4CIDR string, ipv6CIDR string, enableIPv6 bool) (device.Device, int, error) {
	return nil, 0, errors.ErrUnsupported
}
