package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AlirezaDelkhahi/tunssh/internal/dns"
	"github.com/AlirezaDelkhahi/tunssh/internal/recovery"
	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
	"github.com/AlirezaDelkhahi/tunssh/internal/sshclient"
	"github.com/AlirezaDelkhahi/tunssh/internal/tun"
)

const rollbackTimeout = 15 * time.Second

// ErrTUNRollbackIncomplete indicates that a failed TUN start could not completely roll back OS
// routes or DNS settings in-band and requires an out-of-band RestoreTUNSession pass.
var ErrTUNRollbackIncomplete = errors.New("tun controller: rollback incomplete after failed start")

// TUNCapsDTO describes host OS TUN capabilities and elevation requirements for the UI.
type TUNCapsDTO struct {
	Supported              bool   `json:"supported"`
	RequiresElevation      bool   `json:"requires_elevation"`
	HasPersistentCap       bool   `json:"has_persistent_cap"`
	CanEnablePersistentCap bool   `json:"can_enable_persistent_cap"`
	IfaceName              string `json:"iface_name"`
	TUNIPv4                string `json:"tun_ipv4"`
	TUNDNS                 string `json:"tun_dns"`
}

// TUNStartRequest carries the pre-captured network snapshot and routing policy for Full TUN startup.
type TUNStartRequest struct {
	Snapshot      splitroute.NetworkSnapshot `json:"snapshot"`
	BypassIranLAN bool                       `json:"bypass_iran_lan"`
	EnableIPv6    bool                       `json:"enable_ipv6"`
}

// TUNSessionController abstracts local (in-process) and elevated-helper Full TUN lifecycle control.
type TUNSessionController interface {
	Capabilities() TUNCapsDTO
	PrepareSession(ctx context.Context) (splitroute.NetworkSnapshot, error)
	StartTUN(ctx context.Context, req TUNStartRequest, dialer sshclient.TunnelDialer) error
	SetBypass(ctx context.Context, bypassIranLAN bool) error
	Stop(ctx context.Context) error
	Stats() tun.Stats
	IsActiveOnOS(ctx context.Context) (bool, error)
	RestoreFromSnapshot(ctx context.Context, snap splitroute.NetworkSnapshot) error
}

type splitTunnelWithSnapshotApplier interface {
	ApplySplitTunnelWithSnapshot(ctx context.Context, plan splitroute.RoutePlan, snap splitroute.NetworkSnapshot) error
}

// DirectTUNController runs embedded DNS, tun2socks, and split routing directly in-process
// (used when CAP_NET_ADMIN/admin is present or inside the elevated --tun-helper process).
type DirectTUNController struct {
	caps     TUNCapsDTO
	routeMgr splitroute.RouteManager
	newDNS   func() *dns.Server
	newTUN   func() tun.TunRunner
	logger   *slog.Logger

	mu         sync.Mutex
	starting   bool
	active     bool
	stopping   bool
	stopDone   chan struct{}
	dnsSrv     *dns.Server
	dnsCancel  context.CancelFunc
	tunRunner  tun.TunRunner
	activeSnap splitroute.NetworkSnapshot
	bypassIran bool
}

var _ TUNSessionController = (*DirectTUNController)(nil)

// NewDirectTUNController constructs a DirectTUNController with optional dependency overrides.
func NewDirectTUNController(
	caps TUNCapsDTO,
	routeMgr splitroute.RouteManager,
	newDNS func() *dns.Server,
	newTUN func() tun.TunRunner,
	logger *slog.Logger,
) *DirectTUNController {
	if routeMgr == nil {
		routeMgr = splitroute.NewManager()
	}
	if newDNS == nil {
		newDNS = dns.NewServer
	}
	if newTUN == nil {
		newTUN = func() tun.TunRunner { return tun.NewRunner() }
	}
	if logger == nil {
		logger = slog.Default()
	}
	caps = normalizeTUNCaps(caps)
	return &DirectTUNController{
		caps:     caps,
		routeMgr: routeMgr,
		newDNS:   newDNS,
		newTUN:   newTUN,
		logger:   logger,
	}
}

func normalizeTUNCaps(caps TUNCapsDTO) TUNCapsDTO {
	if strings.TrimSpace(caps.IfaceName) == "" {
		caps.IfaceName = splitroute.TUNIfaceName
	}
	if strings.TrimSpace(caps.TUNIPv4) == "" {
		caps.TUNIPv4 = splitroute.TUNIPv4Addr
	}
	if strings.TrimSpace(caps.TUNDNS) == "" {
		caps.TUNDNS = splitroute.TUNDNSServer
	}
	return caps
}

// Capabilities returns the platform TUN capabilities descriptor.
func (c *DirectTUNController) Capabilities() TUNCapsDTO {
	return c.caps
}

// PrepareSession captures the current OS default route and DNS configuration prior to mutation.
func (c *DirectTUNController) PrepareSession(ctx context.Context) (splitroute.NetworkSnapshot, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return splitroute.NetworkSnapshot{}, err
	}
	return c.routeMgr.CaptureNetworkSnapshot(ctx)
}

// StartTUN starts embedded DNS, opens and starts the TUN runner, and applies split-tunnel routes
// with automatic rollback on failure.
func (c *DirectTUNController) StartTUN(ctx context.Context, req TUNStartRequest, dialer sshclient.TunnelDialer) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	if dialer == nil {
		return errors.New("tun controller: TunnelDialer must not be nil")
	}

	plan, snapCopy, err := buildRoutePlanFromSnapshot(req)
	if err != nil {
		return err
	}

	c.mu.Lock()
	if c.starting || c.active || c.stopping {
		c.mu.Unlock()
		return errors.New("tun controller: session is already active or transitioning")
	}
	c.starting = true
	c.mu.Unlock()

	committed := false
	defer func() {
		if !committed {
			c.mu.Lock()
			c.starting = false
			c.mu.Unlock()
		}
	}()

	dnsSrv := c.newDNS()
	if dnsSrv == nil {
		return errors.New("tun controller: DNS server factory returned nil")
	}
	dnsRunCtx, dnsRunCancel := context.WithCancel(context.Background())
	stopDNSStartWatch := context.AfterFunc(ctx, dnsRunCancel)
	bypassUpstreams := slices.Clone(req.Snapshot.OrigDNSServers)
	if len(bypassUpstreams) == 0 && plan.OrigGateway.IsValid() && (plan.OrigGateway.IsPrivate() || plan.OrigGateway.IsLinkLocalUnicast()) {
		bypassUpstreams = []string{plan.OrigGateway.String()}
	}
	dnsCfg := dns.DNSConfig{
		ListenAddr:   dns.DefaultListenAddr,
		TunnelDialer: dialer,
		BypassDialer: interfacePinnedBypassDialer{
			ifaceName:  plan.OrigIfaceName,
			ifaceIndex: plan.OrigIfaceIndex,
		},
		BypassUpstreams: bypassUpstreams,
		BypassIranLAN:   req.BypassIranLAN,
	}
	if err := dnsSrv.Start(dnsRunCtx, dnsCfg); err != nil {
		_ = stopDNSStartWatch()
		dnsRunCancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return fmt.Errorf("tun controller: start embedded DNS: %w", ctxErr)
		}
		return fmt.Errorf("tun controller: start embedded DNS: %w", err)
	}

	tunRunner := c.newTUN()
	if tunRunner == nil {
		_ = stopDNSStartWatch()
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		_ = dnsSrv.Stop(rbCtx)
		dnsRunCancel()
		return errors.New("tun controller: TUN runner factory returned nil")
	}

	tunCfg := tun.Config{
		IfaceName:    plan.TUNIfaceName,
		MTU:          splitroute.TUNMTU,
		IPv4CIDR:     splitroute.TUNIPv4CIDR,
		IPv6CIDR:     splitroute.TUNIPv6CIDR,
		EnableIPv6:   req.EnableIPv6,
		TunnelDialer: dialer,
		DNSUDPAddr:   dnsSrv.UDPAddr(),
		DNSTCPAddr:   dnsSrv.TCPAddr(),
	}
	tunIfIndex, err := tunRunner.Start(ctx, tunCfg)
	if err != nil {
		_ = stopDNSStartWatch()
		rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
		defer cancel()
		stopDNSErr := dnsSrv.Stop(rbCtx)
		dnsRunCancel()
		if stopDNSErr != nil {
			return fmt.Errorf("tun controller: start TUN runner: %w (stop DNS rollback: %v)", err, stopDNSErr)
		}
		return fmt.Errorf("tun controller: start TUN runner: %w", err)
	}

	plan.TUNIfaceIndex = tunIfIndex
	if len(snapCopy.InstalledRoutes) == 0 {
		if routes, routeErr := splitroute.BuildInstalledRoutes(plan); routeErr == nil {
			snapCopy.InstalledRoutes = routes
		}
	}

	var applyErr error
	if err := ctx.Err(); err != nil {
		applyErr = err
	} else {
		applyErr = applySplitTunnel(ctx, c.routeMgr, plan, snapCopy)
	}
	if applyErr != nil {
		_ = stopDNSStartWatch()
		rbErrs := rollbackDirectTUNStart(ctx, c.routeMgr, snapCopy, tunRunner, dnsSrv, dnsRunCancel)
		applyNote := ""
		if runtime.GOOS == "linux" && !c.caps.RequiresElevation && os.Geteuid() != 0 && isLinuxDNSPermissionErr(applyErr) {
			applyNote = " (system DNS changes require root or polkit authorization; clear file capabilities with 'sudo setcap -r <binary>' to use pkexec elevation)"
		}
		if len(rbErrs) > 0 {
			return fmt.Errorf("tun controller: apply split tunnel: %w%s (%w: %w)", applyErr, applyNote, ErrTUNRollbackIncomplete, errors.Join(rbErrs...))
		}
		return fmt.Errorf("tun controller: apply split tunnel: %w%s", applyErr, applyNote)
	}

	// Detach startup cancellation watcher only after committing; if ctx already canceled
	// right before detaching, roll back cleanly instead of leaking an unowned DNS/TUN session.
	if !stopDNSStartWatch() || ctx.Err() != nil {
		rbErrs := rollbackDirectTUNStart(ctx, c.routeMgr, snapCopy, tunRunner, dnsSrv, dnsRunCancel)
		cause := ctx.Err()
		if cause == nil {
			cause = context.Canceled
		}
		if len(rbErrs) > 0 {
			return fmt.Errorf("%w (%w: %w)", cause, ErrTUNRollbackIncomplete, errors.Join(rbErrs...))
		}
		return cause
	}

	c.mu.Lock()
	c.starting = false
	c.active = true
	c.dnsSrv = dnsSrv
	c.dnsCancel = dnsRunCancel
	c.tunRunner = tunRunner
	c.activeSnap = snapCopy
	c.bypassIran = req.BypassIranLAN
	committed = true
	c.mu.Unlock()

	return nil
}

func applySplitTunnel(ctx context.Context, mgr splitroute.RouteManager, plan splitroute.RoutePlan, snap splitroute.NetworkSnapshot) error {
	if applier, ok := mgr.(splitTunnelWithSnapshotApplier); ok {
		return applier.ApplySplitTunnelWithSnapshot(ctx, plan, snap)
	}
	return mgr.ApplySplitTunnel(ctx, plan)
}

// SetBypass dynamically toggles Iran/LAN bypass on both OS routes and the embedded DNS server.
func (c *DirectTUNController) SetBypass(ctx context.Context, bypassIranLAN bool) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	if !c.active || c.stopping {
		c.mu.Unlock()
		return errors.New("tun controller: session is not active")
	}
	dnsSrv := c.dnsSrv
	snap := cloneNetworkSnapshot(c.activeSnap)
	c.mu.Unlock()

	if err := c.routeMgr.SetBypassIranLAN(ctx, snap, bypassIranLAN); err != nil {
		return fmt.Errorf("tun controller: set bypass routes: %w", err)
	}
	if dnsSrv != nil {
		dnsSrv.SetBypassIranLAN(bypassIranLAN)
	}

	c.mu.Lock()
	if c.active && c.dnsSrv == dnsSrv {
		c.bypassIran = bypassIranLAN
	}
	c.mu.Unlock()
	return nil
}

// Stop idempotently restores OS routes/DNS first, then stops the TUN runner and embedded DNS server.
func (c *DirectTUNController) Stop(ctx context.Context) error {
	ctx = normalizeContext(ctx)

	c.mu.Lock()
	if c.stopping {
		stopDone := c.stopDone
		c.mu.Unlock()
		if stopDone != nil {
			select {
			case <-stopDone:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}
	if !c.active {
		if c.starting {
			c.mu.Unlock()
			return errors.New("tun controller: cannot stop while start is in progress")
		}
		c.mu.Unlock()
		return nil
	}

	c.active = false
	c.stopping = true
	stopDone := make(chan struct{})
	c.stopDone = stopDone
	dnsSrv := c.dnsSrv
	dnsCancel := c.dnsCancel
	tunRunner := c.tunRunner
	snap := cloneNetworkSnapshot(c.activeSnap)
	c.dnsSrv = nil
	c.dnsCancel = nil
	c.tunRunner = nil
	c.activeSnap = splitroute.NetworkSnapshot{}
	c.bypassIran = false
	c.mu.Unlock()

	var errs []error
	if err := c.routeMgr.RestoreNetwork(ctx, snap); err != nil {
		errs = append(errs, fmt.Errorf("restore network: %w", err))
	}
	if tunRunner != nil {
		if err := tunRunner.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop TUN runner: %w", err))
		}
	}
	if dnsSrv != nil {
		if err := dnsSrv.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop DNS server: %w", err))
		}
	}
	if dnsCancel != nil {
		dnsCancel()
	}

	c.mu.Lock()
	c.stopping = false
	c.stopDone = nil
	close(stopDone)
	c.mu.Unlock()

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Stats returns the current TUN runner status and byte counters.
func (c *DirectTUNController) Stats() tun.Stats {
	c.mu.Lock()
	tr := c.tunRunner
	c.mu.Unlock()
	if tr == nil {
		return tun.Stats{}
	}
	return tr.Stats()
}

// IsActiveOnOS checks whether the TUN interface or split routes are currently present on the OS.
func (c *DirectTUNController) IsActiveOnOS(ctx context.Context) (bool, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return c.routeMgr.IsTUNStateActive(ctx)
}

// RestoreFromSnapshot idempotently restores OS routes and DNS from a saved snapshot.
func (c *DirectTUNController) RestoreFromSnapshot(ctx context.Context, snap splitroute.NetworkSnapshot) error {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.routeMgr.RestoreNetwork(ctx, snap)
}

type interfacePinnedBypassDialer struct {
	ifaceName  string
	ifaceIndex int
}

func (d interfacePinnedBypassDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var control func(network, address string, c syscall.RawConn) error
	if host, _, err := net.SplitHostPort(address); err == nil {
		if ip, parseErr := netip.ParseAddr(strings.TrimSpace(host)); parseErr == nil {
			u := ip.Unmap()
			if !u.IsLoopback() && (strings.TrimSpace(d.ifaceName) != "" || d.ifaceIndex > 0) {
				control = splitroute.BindToInterfaceControl(d.ifaceName, d.ifaceIndex, u.Is6())
			}
		} else if strings.TrimSpace(d.ifaceName) != "" || d.ifaceIndex > 0 {
			control = splitroute.BindToInterfaceControl(d.ifaceName, d.ifaceIndex, false)
		}
	} else if strings.TrimSpace(d.ifaceName) != "" || d.ifaceIndex > 0 {
		control = splitroute.BindToInterfaceControl(d.ifaceName, d.ifaceIndex, false)
	}

	nd := &net.Dialer{
		Timeout: dns.DefaultQueryTimeout,
		Control: control,
	}
	return nd.DialContext(ctx, network, address)
}

func buildRoutePlanFromSnapshot(req TUNStartRequest) (splitroute.RoutePlan, splitroute.NetworkSnapshot, error) {
	snap := cloneNetworkSnapshot(req.Snapshot)

	vpsIP, err := parseRequiredIP(snap.VPSPeerIP, "vps_peer_ip")
	if err != nil {
		return splitroute.RoutePlan{}, splitroute.NetworkSnapshot{}, err
	}
	origGW4, err := parseOptionalIP(snap.OrigGateway, "orig_gateway")
	if err != nil {
		return splitroute.RoutePlan{}, splitroute.NetworkSnapshot{}, err
	}
	origGW6, err := parseOptionalIP(snap.OrigGateway6, "orig_gateway6")
	if err != nil {
		return splitroute.RoutePlan{}, splitroute.NetworkSnapshot{}, err
	}

	origIface := strings.TrimSpace(snap.OrigIfaceName)
	if origIface == "" && snap.OrigIfaceIndex <= 0 {
		return splitroute.RoutePlan{}, splitroute.NetworkSnapshot{}, errors.New("tun controller: snapshot missing orig_iface_name and orig_iface_index")
	}

	tunIface := strings.TrimSpace(snap.TUNIfaceName)
	if tunIface == "" {
		tunIface = splitroute.TUNIfaceName
		snap.TUNIfaceName = tunIface
	}

	origDNS := make([]netip.Addr, 0, len(snap.OrigDNSServers))
	for _, raw := range snap.OrigDNSServers {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if host, _, splitErr := net.SplitHostPort(trimmed); splitErr == nil {
			trimmed = host
		}
		if addr, parseErr := netip.ParseAddr(trimmed); parseErr == nil && addr.IsValid() {
			origDNS = append(origDNS, addr.Unmap())
		}
	}

	plan := splitroute.RoutePlan{
		VPSPeerIP:      vpsIP,
		OrigGateway:    origGW4,
		OrigGateway6:   origGW6,
		OrigIfaceName:  origIface,
		OrigIfaceIndex: snap.OrigIfaceIndex,
		OrigDNSServers: origDNS,
		TUNIfaceName:   tunIface,
		BypassIranLAN:  req.BypassIranLAN,
		EnableIPv6:     req.EnableIPv6,
	}
	return plan, snap, nil
}

func parseRequiredIP(raw, field string) (netip.Addr, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return netip.Addr{}, fmt.Errorf("tun controller: snapshot missing %s", field)
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("tun controller: invalid %s %q", field, raw)
	}
	return addr.Unmap(), nil
}

func parseOptionalIP(raw, field string) (netip.Addr, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return netip.Addr{}, nil
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("tun controller: invalid %s %q", field, raw)
	}
	return addr.Unmap(), nil
}

func cloneNetworkSnapshot(s splitroute.NetworkSnapshot) splitroute.NetworkSnapshot {
	out := s
	out.OrigDNSServers = slices.Clone(s.OrigDNSServers)
	out.InstalledRoutes = slices.Clone(s.InstalledRoutes)
	if s.WinAdapterDNSBackups != nil {
		out.WinAdapterDNSBackups = make([]splitroute.WinAdapterDNSBackup, len(s.WinAdapterDNSBackups))
		for i, b := range s.WinAdapterDNSBackups {
			out.WinAdapterDNSBackups[i] = splitroute.WinAdapterDNSBackup{
				IfaceIndex: b.IfaceIndex,
				IfaceName:  b.IfaceName,
				IPv4DNS:    slices.Clone(b.IPv4DNS),
				IPv6DNS:    slices.Clone(b.IPv6DNS),
			}
		}
	}
	if s.LinuxDNSBackups != nil {
		out.LinuxDNSBackups = make([]splitroute.LinuxDNSBackup, len(s.LinuxDNSBackups))
		for i, b := range s.LinuxDNSBackups {
			out.LinuxDNSBackups[i] = splitroute.LinuxDNSBackup{
				IfIndex:      b.IfIndex,
				IfName:       b.IfName,
				DNSServers:   slices.Clone(b.DNSServers),
				DefaultRoute: b.DefaultRoute,
			}
		}
	}
	return out
}

// NetworkSnapshotToRecovery converts a splitroute.NetworkSnapshot into a recovery.TUNSnapshot.
func NetworkSnapshotToRecovery(s splitroute.NetworkSnapshot) recovery.TUNSnapshot {
	out := recovery.TUNSnapshot{
		VPSPeerIP:        s.VPSPeerIP,
		OrigGateway:      s.OrigGateway,
		OrigGateway6:     s.OrigGateway6,
		OrigIfaceName:    s.OrigIfaceName,
		OrigIfaceIndex:   s.OrigIfaceIndex,
		OrigDNSServers:   slices.Clone(s.OrigDNSServers),
		DNSStrategy:      s.DNSStrategy,
		ResolvConfBackup: s.ResolvConfBackup,
		TUNIfaceName:     s.TUNIfaceName,
		InstalledRoutes:  slices.Clone(s.InstalledRoutes),
	}
	if s.WinAdapterDNSBackups != nil {
		out.WinAdapterDNSBackups = make([]recovery.WinAdapterDNSBackup, len(s.WinAdapterDNSBackups))
		for i, b := range s.WinAdapterDNSBackups {
			out.WinAdapterDNSBackups[i] = recovery.WinAdapterDNSBackup{
				IfaceIndex: b.IfaceIndex,
				IfaceName:  b.IfaceName,
				IPv4DNS:    slices.Clone(b.IPv4DNS),
				IPv6DNS:    slices.Clone(b.IPv6DNS),
			}
		}
	}
	if s.LinuxDNSBackups != nil {
		out.LinuxDNSBackups = make([]recovery.LinuxDNSBackup, len(s.LinuxDNSBackups))
		for i, b := range s.LinuxDNSBackups {
			out.LinuxDNSBackups[i] = recovery.LinuxDNSBackup{
				IfIndex:      b.IfIndex,
				IfName:       b.IfName,
				DNSServers:   slices.Clone(b.DNSServers),
				DefaultRoute: b.DefaultRoute,
			}
		}
	}
	return out
}

// RecoverySnapshotToNetwork converts a recovery.TUNSnapshot into a splitroute.NetworkSnapshot.
func RecoverySnapshotToNetwork(r recovery.TUNSnapshot) splitroute.NetworkSnapshot {
	out := splitroute.NetworkSnapshot{
		VPSPeerIP:        r.VPSPeerIP,
		OrigGateway:      r.OrigGateway,
		OrigGateway6:     r.OrigGateway6,
		OrigIfaceName:    r.OrigIfaceName,
		OrigIfaceIndex:   r.OrigIfaceIndex,
		OrigDNSServers:   slices.Clone(r.OrigDNSServers),
		DNSStrategy:      r.DNSStrategy,
		ResolvConfBackup: r.ResolvConfBackup,
		TUNIfaceName:     r.TUNIfaceName,
		InstalledRoutes:  slices.Clone(r.InstalledRoutes),
	}
	if r.WinAdapterDNSBackups != nil {
		out.WinAdapterDNSBackups = make([]splitroute.WinAdapterDNSBackup, len(r.WinAdapterDNSBackups))
		for i, b := range r.WinAdapterDNSBackups {
			out.WinAdapterDNSBackups[i] = splitroute.WinAdapterDNSBackup{
				IfaceIndex: b.IfaceIndex,
				IfaceName:  b.IfaceName,
				IPv4DNS:    slices.Clone(b.IPv4DNS),
				IPv6DNS:    slices.Clone(b.IPv6DNS),
			}
		}
	}
	if r.LinuxDNSBackups != nil {
		out.LinuxDNSBackups = make([]splitroute.LinuxDNSBackup, len(r.LinuxDNSBackups))
		for i, b := range r.LinuxDNSBackups {
			out.LinuxDNSBackups[i] = splitroute.LinuxDNSBackup{
				IfIndex:      b.IfIndex,
				IfName:       b.IfName,
				DNSServers:   slices.Clone(b.DNSServers),
				DefaultRoute: b.DefaultRoute,
			}
		}
	}
	return out
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func rollbackDirectTUNStart(
	ctx context.Context,
	routeMgr splitroute.RouteManager,
	snap splitroute.NetworkSnapshot,
	tunRunner tun.TunRunner,
	dnsSrv *dns.Server,
	dnsRunCancel context.CancelFunc,
) []error {
	rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	var rbErrs []error
	if rErr := routeMgr.RestoreNetwork(rbCtx, snap); rErr != nil {
		rbErrs = append(rbErrs, fmt.Errorf("restore network: %w", rErr))
	}
	if tErr := tunRunner.Stop(rbCtx); tErr != nil {
		rbErrs = append(rbErrs, fmt.Errorf("stop TUN runner: %w", tErr))
	}
	if dErr := dnsSrv.Stop(rbCtx); dErr != nil {
		rbErrs = append(rbErrs, fmt.Errorf("stop DNS: %w", dErr))
	}
	dnsRunCancel()
	return rbErrs
}

func isLinuxDNSPermissionErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "interactive authentication required")
}
