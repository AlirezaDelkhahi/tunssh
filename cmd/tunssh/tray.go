package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/AlirezaDelkhahi/tunssh/internal/app"
	"github.com/AlirezaDelkhahi/tunssh/internal/sshclient"
	"github.com/energye/systray"
)

type trayActions struct {
	OnToggleConnect func()
	OnRestore       func()
	OnShowWindow    func()
	OnQuit          func()
}

type trayIconSet struct {
	disconnected []byte
	connecting   []byte
	connected    []byte
	errState     []byte
}

type trayController struct {
	actions trayActions
	icons   trayIconSet

	mu        sync.Mutex
	started   bool
	ready     bool
	endFn     func()
	toggle    *systray.MenuItem
	modeProxy *systray.MenuItem
	modeTUN   *systray.MenuItem
	restore   *systray.MenuItem
	openWin   *systray.MenuItem
	quitItem  *systray.MenuItem
	status    app.TunnelStatusDTO

	stopOnce sync.Once
	stopped  atomic.Bool
}

func newTrayController(actions trayActions) *trayController {
	return &trayController{
		actions: actions,
		icons: trayIconSet{
			disconnected: buildTrayIcon(color.NRGBA{R: 0x64, G: 0x74, B: 0x8B, A: 0xFF}),
			connecting:   buildTrayIcon(color.NRGBA{R: 0xF5, G: 0x9E, B: 0x0B, A: 0xFF}),
			connected:    buildTrayIcon(color.NRGBA{R: 0x22, G: 0xC5, B: 0x5E, A: 0xFF}),
			errState:     buildTrayIcon(color.NRGBA{R: 0xEF, G: 0x44, B: 0x44, A: 0xFF}),
		},
		status: app.TunnelStatusDTO{
			State: string(sshclient.StateDisconnected),
			Mode:  "proxy",
		},
	}
}

func (t *trayController) Start() bool {
	if !canStartTray() {
		return false
	}

	t.mu.Lock()
	if t.started || t.stopped.Load() {
		t.mu.Unlock()
		return t.started
	}
	t.started = true
	t.mu.Unlock()

	start, end := systray.RunWithExternalLoop(t.onReady, t.onExit)
	t.mu.Lock()
	t.endFn = end
	t.mu.Unlock()

	start()
	return true
}

func (t *trayController) Stop() {
	t.stopped.Store(true)
	t.stopOnce.Do(func() {
		t.mu.Lock()
		started := t.started
		endFn := t.endFn
		t.ready = false
		t.mu.Unlock()
		if started && endFn != nil {
			endFn()
		}
	})
}

func (t *trayController) UpdateStatus(status app.TunnelStatusDTO) {
	t.mu.Lock()
	t.status = status
	ready := t.ready
	toggle := t.toggle
	t.mu.Unlock()

	if !ready {
		return
	}
	t.applyStatusUI(status, toggle)
}

func (t *trayController) onReady() {
	if t.stopped.Load() {
		return
	}

	systray.SetTitle("tunssh")
	systray.SetTooltip("tunssh — Disconnected")
	systray.SetIcon(t.icons.disconnected)
	systray.SetOnClick(func(systray.IMenu) {
		if t.actions.OnShowWindow != nil {
			go t.actions.OnShowWindow()
		}
	})

	toggle := systray.AddMenuItem("Connect", "Connect or disconnect the active SSH tunnel")
	toggle.Click(func() {
		if t.actions.OnToggleConnect != nil {
			go t.actions.OnToggleConnect()
		}
	})

	modeProxy := systray.AddMenuItemCheckbox("Mode: System Proxy", "Unprivileged local SOCKS5/HTTP proxy mode", true)
	modeProxy.Disable()

	modeTUN := systray.AddMenuItem("Full TUN (Milestone 2)", "Full device TUN routing arrives in Milestone 2")
	modeTUN.Disable()

	systray.AddSeparator()

	restore := systray.AddMenuItem("Restore Network", "Verify and restore OS proxy configuration")
	restore.Click(func() {
		if t.actions.OnRestore != nil {
			go t.actions.OnRestore()
		}
	})

	openWin := systray.AddMenuItem("Open tunssh", "Show the tunssh desktop window")
	openWin.Click(func() {
		if t.actions.OnShowWindow != nil {
			go t.actions.OnShowWindow()
		}
	})

	systray.AddSeparator()

	quitItem := systray.AddMenuItem("Quit", "Disconnect tunnel, restore network, and exit tunssh")
	quitItem.Click(func() {
		if t.actions.OnQuit != nil {
			go t.actions.OnQuit()
		}
	})

	t.mu.Lock()
	t.toggle = toggle
	t.modeProxy = modeProxy
	t.modeTUN = modeTUN
	t.restore = restore
	t.openWin = openWin
	t.quitItem = quitItem
	t.ready = true
	status := t.status
	t.mu.Unlock()

	t.applyStatusUI(status, toggle)
}

func (t *trayController) onExit() {
	t.mu.Lock()
	t.ready = false
	t.mu.Unlock()
}

func (t *trayController) applyStatusUI(status app.TunnelStatusDTO, toggle *systray.MenuItem) {
	icon := t.icons.disconnected
	tooltip := "tunssh — Disconnected"
	toggleTitle := "Connect"

	switch status.State {
	case string(sshclient.StateConnected):
		icon = t.icons.connected
		tooltip = fmt.Sprintf("tunssh — Connected (:%d / :%d)", status.SOCKSPort, status.HTTPPort)
		toggleTitle = "Disconnect"
	case string(sshclient.StateConnecting):
		icon = t.icons.connecting
		tooltip = "tunssh — Connecting..."
		toggleTitle = "Cancel Connection"
	case string(sshclient.StateReconnecting):
		icon = t.icons.connecting
		tooltip = fmt.Sprintf("tunssh — Reconnecting (attempt #%d)", max(1, status.Attempt))
		toggleTitle = "Cancel Reconnect"
	case string(sshclient.StateError):
		icon = t.icons.errState
		tooltip = "tunssh — Action Required"
		toggleTitle = "Connect"
	}

	systray.SetIcon(icon)
	systray.SetTooltip(tooltip)
	if toggle != nil {
		toggle.SetTitle(toggleTitle)
	}
}

// buildTrayIcon draws a 32x32 state-colored circular badge with a dark ring and inner specular dot.
func buildTrayIcon(fill color.NRGBA) []byte {
	const size = 32
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	ringColor := color.NRGBA{R: 0x0B, G: 0x0F, B: 0x17, A: 0xFF}
	centerColor := color.NRGBA{R: 0xF8, G: 0xFA, B: 0xFC, A: 0xEB}

	const cx, cy = 15.5, 15.5
	const outerR2 = 14.0 * 14.0
	const innerR2 = 11.2 * 11.2
	const dotR2 = 4.2 * 4.2

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - cx
			dy := float64(y) - cy
			d2 := dx*dx + dy*dy
			switch {
			case d2 <= dotR2:
				img.SetNRGBA(x, y, centerColor)
			case d2 <= innerR2:
				img.SetNRGBA(x, y, fill)
			case d2 <= outerR2:
				img.SetNRGBA(x, y, ringColor)
			}
		}
	}

	var pngBuf bytes.Buffer
	_ = png.Encode(&pngBuf, img)
	pngBytes := pngBuf.Bytes()

	if runtime.GOOS != "windows" {
		return pngBytes
	}
	return wrapPNGAsICO(pngBytes, size, size)
}

func wrapPNGAsICO(pngData []byte, width, height uint8) []byte {
	const headerLen = 6 + 16
	out := make([]byte, headerLen+len(pngData))
	binary.LittleEndian.PutUint16(out[0:2], 0) // Reserved
	binary.LittleEndian.PutUint16(out[2:4], 1) // Type = ICO
	binary.LittleEndian.PutUint16(out[4:6], 1) // Count = 1
	out[6] = width
	out[7] = height
	out[8] = 0                                    // ColorCount
	out[9] = 0                                    // Reserved
	binary.LittleEndian.PutUint16(out[10:12], 1)  // Planes
	binary.LittleEndian.PutUint16(out[12:14], 32) // BitCount
	binary.LittleEndian.PutUint32(out[14:18], uint32(len(pngData)))
	binary.LittleEndian.PutUint32(out[18:22], headerLen)
	copy(out[headerLen:], pngData)
	return out
}
