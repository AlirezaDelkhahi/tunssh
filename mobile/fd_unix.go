//go:build unix

package mobile

import "syscall"

func closeFD(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}
