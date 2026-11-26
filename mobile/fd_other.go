//go:build !unix

package mobile

func closeFD(int) {}
