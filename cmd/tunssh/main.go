package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/AlirezaDelkhahi/tunssh/frontend"
	"github.com/AlirezaDelkhahi/tunssh/internal/app"
	"github.com/AlirezaDelkhahi/tunssh/internal/profile"
	"github.com/AlirezaDelkhahi/tunssh/internal/proxy"
	"github.com/AlirezaDelkhahi/tunssh/internal/recovery"
	"github.com/AlirezaDelkhahi/tunssh/internal/sshclient"
	"github.com/AlirezaDelkhahi/tunssh/internal/sysproxy"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type wailsAndTrayBridge struct {
	ctxMu sync.RWMutex
	ctx   context.Context

	tray          *trayController
	lastState     atomic.Value
	lastProfileID atomic.Value
}

func newWailsAndTrayBridge() *wailsAndTrayBridge {
	b := &wailsAndTrayBridge{}
	b.lastState.Store(string(sshclient.StateDisconnected))
	b.lastProfileID.Store("")
	return b
}

func (b *wailsAndTrayBridge) SetCtx(ctx context.Context) {
	b.ctxMu.Lock()
	b.ctx = ctx
	b.ctxMu.Unlock()
}

func (b *wailsAndTrayBridge) SetTray(tray *trayController) {
	b.ctxMu.Lock()
	b.tray = tray
	b.ctxMu.Unlock()
}

func (b *wailsAndTrayBridge) Context() context.Context {
	b.ctxMu.RLock()
	defer b.ctxMu.RUnlock()
	return b.ctx
}

func (b *wailsAndTrayBridge) CurrentState() string {
	v, _ := b.lastState.Load().(string)
	return v
}

func (b *wailsAndTrayBridge) LastProfileID() string {
	v, _ := b.lastProfileID.Load().(string)
	return v
}

func (b *wailsAndTrayBridge) Emit(eventName string, data any) {
	if eventName == "tunnel:status" {
		if status, ok := data.(app.TunnelStatusDTO); ok {
			b.lastState.Store(status.State)
			if status.ProfileID != "" {
				b.lastProfileID.Store(status.ProfileID)
			}
			b.ctxMu.RLock()
			tray := b.tray
			b.ctxMu.RUnlock()
			if tray != nil {
				tray.UpdateStatus(status)
			}
		}
	}

	b.ctxMu.RLock()
	ctx := b.ctx
	b.ctxMu.RUnlock()
	if ctx != nil {
		wailsRuntime.EventsEmit(ctx, eventName, data)
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "tunssh: fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	distFS, err := frontend.DistFS()
	if err != nil {
		return fmt.Errorf("load embedded frontend assets: %w", err)
	}

	configDir, err := recovery.DefaultConfigDir()
	if err != nil {
		return fmt.Errorf("resolve config directory: %w", err)
	}

	profileStore, err := profile.NewFileStore(configDir)
	if err != nil {
		return fmt.Errorf("initialize profile store: %w", err)
	}

	secretStore := profile.NewAutoSecretStore(configDir)
	engine := sshclient.NewClient()
	sysProxy := sysproxy.NewManager()

	recStore, err := recovery.NewFileRecoveryStore(configDir)
	if err != nil {
		return fmt.Errorf("initialize recovery store: %w", err)
	}
	restorer := recovery.NewRestorer(recStore, sysProxy)

	scrubber := app.NewSecretScrubber()
	logBuffer := app.NewLogBuffer(app.DefaultLogBufferCapacity)
	bridge := newWailsAndTrayBridge()

	redactingHandler := app.NewRedactingHandler(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}),
		scrubber,
		logBuffer,
		func(entry app.LogEntryDTO) {
			bridge.Emit("tunnel:log", entry)
		},
	)
	logger := slog.New(redactingHandler)

	appSvc, err := app.NewAppService(app.Config{
		Profiles:  profileStore,
		Secrets:   secretStore,
		Engine:    engine,
		SysProxy:  sysProxy,
		Restorer:  restorer,
		Emitter:   bridge,
		Scrubber:  scrubber,
		LogBuffer: logBuffer,
		Logger:    logger,
		ProxyConfig: proxy.Config{
			SOCKSAddr: proxy.DefaultSOCKSAddr,
			HTTPAddr:  proxy.DefaultHTTPAddr,
		},
		FilePicker: func(ctx context.Context) (string, error) {
			dialogCtx := ctx
			if current := bridge.Context(); current != nil {
				dialogCtx = current
			}
			return wailsRuntime.OpenFileDialog(dialogCtx, wailsRuntime.OpenDialogOptions{
				Title: "Select SSH Private Key",
				Filters: []wailsRuntime.FileFilter{
					{DisplayName: "SSH Private Keys (*.pem, *.key, id_*)", Pattern: "*.pem;*.key;id_*;*"},
				},
			})
		},
	})
	if err != nil {
		return fmt.Errorf("initialize application service: %w", err)
	}

	var (
		quitting     atomic.Bool
		trayStarted  atomic.Bool
		shutdownOnce sync.Once
		sigCancel    context.CancelFunc
	)

	var tray *trayController
	showWindow := func() {
		if ctx := bridge.Context(); ctx != nil {
			wailsRuntime.WindowShow(ctx)
			wailsRuntime.WindowUnminimise(ctx)
		}
	}

	performShutdown := func(ctx context.Context) {
		shutdownOnce.Do(func() {
			if sigCancel != nil {
				sigCancel()
			}
			appSvc.Shutdown(ctx)
			if tray != nil {
				tray.Stop()
			}
		})
	}

	tray = newTrayController(trayActions{
		OnToggleConnect: func() {
			if isActiveTunnelState(bridge.CurrentState()) {
				if err := appSvc.Disconnect(); err != nil {
					logger.Warn("Tray disconnect returned error", "err", err)
				}
				return
			}
			profileID := bridge.LastProfileID()
			if profileID == "" {
				profiles, listErr := appSvc.ListProfiles()
				if listErr != nil || len(profiles) == 0 {
					showWindow()
					return
				}
				profileID = profiles[0].ID
			}
			if err := appSvc.Connect(profileID, string(profile.ModeProxy)); err != nil {
				logger.Warn("Tray connect returned error", "err", err)
				showWindow()
			}
		},
		OnRestore: func() {
			if err := appSvc.RestoreNetwork(); err != nil {
				logger.Error("Tray network restore failed", "err", err)
			}
		},
		OnShowWindow: showWindow,
		OnQuit: func() {
			quitting.Store(true)
			if ctx := bridge.Context(); ctx != nil {
				wailsRuntime.Quit(ctx)
			}
		},
	})
	bridge.SetTray(tray)

	return wails.Run(&options.App{
		Title:            "tunssh",
		Width:            460,
		Height:           680,
		MinWidth:         420,
		MinHeight:        620,
		BackgroundColour: &options.RGBA{R: 11, G: 15, B: 23, A: 255},
		AssetServer: &assetserver.Options{
			Assets: distFS,
		},
		Bind: []any{appSvc},
		OnStartup: func(ctx context.Context) {
			bridge.SetCtx(ctx)
			appSvc.Startup(ctx)

			if boot, bootErr := appSvc.GetBootstrapState(); bootErr == nil {
				bridge.lastState.Store(boot.Status.State)
				if boot.Status.ProfileID != "" {
					bridge.lastProfileID.Store(boot.Status.ProfileID)
				} else if len(boot.Profiles) > 0 {
					bridge.lastProfileID.Store(boot.Profiles[0].ID)
				}
				tray.UpdateStatus(boot.Status)
			}

			if tray.Start() {
				trayStarted.Store(true)
			} else {
				logger.Info("System tray unavailable on current session; running window-only mode")
			}

			sigCtx, cancel := context.WithCancel(context.Background())
			sigCancel = cancel
			sigCh := make(chan os.Signal, 2)
			signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
			go func() {
				defer signal.Stop(sigCh)
				select {
				case <-sigCtx.Done():
					return
				case sig := <-sigCh:
					logger.Info("Received shutdown signal; restoring OS proxy state", "signal", sig.String())
					quitting.Store(true)
					cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
					performShutdown(cleanCtx)
					cleanCancel()
					wailsRuntime.Quit(ctx)
				}
			}()
		},
		OnBeforeClose: func(ctx context.Context) bool {
			if !quitting.Load() && trayStarted.Load() && isActiveTunnelState(bridge.CurrentState()) {
				wailsRuntime.WindowHide(ctx)
				return true
			}
			return false
		},
		OnShutdown: func(ctx context.Context) {
			quitting.Store(true)
			performShutdown(ctx)
		},
	})
}

func isActiveTunnelState(state string) bool {
	switch state {
	case string(sshclient.StateConnected),
		string(sshclient.StateConnecting),
		string(sshclient.StateReconnecting):
		return true
	default:
		return false
	}
}
