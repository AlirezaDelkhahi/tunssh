package sshclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultWatchdogInterval  = 10 * time.Second
	defaultWatchdogTimeout   = 5 * time.Second
	defaultWatchdogMaxMissed = 2
	probeDrainGrace          = 50 * time.Millisecond
)

// WatchdogConfig tunes active keepalive@openssh.com probing.
type WatchdogConfig struct {
	Interval  time.Duration
	Timeout   time.Duration
	MaxMissed int
}

func (c WatchdogConfig) withDefaults() WatchdogConfig {
	if c.Interval <= 0 {
		c.Interval = defaultWatchdogInterval
	}
	if c.Timeout <= 0 {
		c.Timeout = defaultWatchdogTimeout
	}
	if c.MaxMissed <= 0 {
		c.MaxMissed = defaultWatchdogMaxMissed
	}
	return c
}

type probeResult struct {
	rtt time.Duration
	err error
}

// StartWatchdog launches a single keepalive watchdog goroutine bound to ctx.
// It enforces at most one in-flight SendRequest helper goroutine at a time so
// wedged probes serialized on x/crypto/ssh globalSentMu cannot pile up.
func StartWatchdog(
	ctx context.Context,
	client *ssh.Client,
	rawConn net.Conn,
	cfg WatchdogConfig,
	onRTT func(time.Duration),
	onDead func(error),
) (wait func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg = cfg.withDefaults()
	done := make(chan struct{})

	go func() {
		defer close(done)
		if client == nil {
			if onDead != nil {
				onDead(errors.New("sshclient: watchdog started with nil client"))
			}
			return
		}

		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()

		probeCh := make(chan probeResult, 1)
		var probeWg sync.WaitGroup
		inFlight := false
		missedTicks := 0
		var lastErr error

		drainOnCancel := func() {
			if !inFlight {
				probeWg.Wait()
				return
			}
			drainTimer := time.NewTimer(probeDrainGrace)
			select {
			case <-probeCh:
				drainTimer.Stop()
				probeWg.Wait()
			case <-drainTimer.C:
			}
		}

		for {
			select {
			case <-ctx.Done():
				drainOnCancel()
				return
			case <-probeCh:
				// A previously timed-out probe finished between ticks; allow a fresh probe on the next tick.
				inFlight = false
			case <-ticker.C:
				if !inFlight {
					inFlight = true
					probeWg.Add(1)
					go func() {
						defer probeWg.Done()
						start := time.Now()
						_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
						probeCh <- probeResult{rtt: time.Since(start), err: err}
					}()
				}

				timeoutTimer := time.NewTimer(cfg.Timeout)
				select {
				case <-ctx.Done():
					timeoutTimer.Stop()
					drainOnCancel()
					return
				case res := <-probeCh:
					timeoutTimer.Stop()
					inFlight = false
					if res.err != nil {
						missedTicks++
						lastErr = res.err
					} else {
						missedTicks = 0
						lastErr = nil
						if onRTT != nil {
							onRTT(res.rtt)
						}
					}
				case <-timeoutTimer.C:
					// Keep inFlight = true while the wedged SendRequest helper remains blocked.
					missedTicks++
					lastErr = fmt.Errorf("keepalive probe timed out after %s: %w", cfg.Timeout, context.DeadlineExceeded)
				}

				if missedTicks >= cfg.MaxMissed {
					if rawConn != nil {
						_ = rawConn.Close()
					} else {
						_ = client.Close()
					}
					probeWg.Wait()
					if onDead != nil {
						onDead(lastErr)
					}
					return
				}
			}
		}
	}()

	return func() { <-done }
}
