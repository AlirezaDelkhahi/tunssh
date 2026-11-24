//go:build linux

package main

import (
	"os"
	"strings"

	dbus "github.com/godbus/dbus/v5"
)

func canStartTray() bool {
	if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) == "" {
		return false
	}
	conn, err := dbus.ConnectSessionBus()
	if err != nil || conn == nil {
		return false
	}
	_ = conn.Close()
	return true
}
