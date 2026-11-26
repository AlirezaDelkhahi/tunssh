//go:build !linux

package tun

import (
	"errors"

	"github.com/xjasonlyu/tun2socks/v2/core/device"
)

// NewFDRunner is unsupported on non-Linux targets.
func NewFDRunner(fd int) *Runner {
	return &Runner{
		openDevice: func(string, int, string, string, bool) (device.Device, int, error) {
			return nil, 0, errors.ErrUnsupported
		},
	}
}
