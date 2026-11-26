// Package mobile provides the gomobile-compatible Android bridge over tunssh's
// SSH, embedded DNS, FD-backed TUN runner, IPv4 CIDR complement, and share-link packages.
package mobile

// SocketProtector protects outbound sockets from VPN routing loops (Android VpnService.protect).
type SocketProtector interface {
	Protect(fd int32) bool
}

// EventListener receives asynchronous JSON status, host-key prompt, and log events from Engine.
type EventListener interface {
	OnStatusChanged(statusJSON string)
	OnHostKeyPrompt(promptJSON string)
	OnLog(entryJSON string)
}

type hostKeyPinDTO struct {
	Algorithm string `json:"algorithm"`
	SHA256    string `json:"sha256"`
}

type connectConfigDTO struct {
	ProfileID     string         `json:"profile_id"`
	Host          string         `json:"host"`
	Port          int            `json:"port"`
	Username      string         `json:"username"`
	AuthType      string         `json:"auth_type"`
	Password      string         `json:"password"`
	PrivateKey    string         `json:"private_key"`
	KeyPassphrase string         `json:"key_passphrase"`
	PinnedHostKey *hostKeyPinDTO `json:"pinned_host_key"`
	BypassIranLAN bool           `json:"bypass_iran_lan"`
	EnableIPv6    bool           `json:"enable_ipv6"`
	UpstreamDNS   []string       `json:"upstream_dns"`
}

type errorDTO struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	ActionHint string `json:"action_hint"`
	Retryable  bool   `json:"retryable"`
}

type statusDTO struct {
	State           string    `json:"state"`
	ProfileID       string    `json:"profile_id"`
	Attempt         int       `json:"attempt"`
	RTTMs           int64     `json:"rtt_ms"`
	RxBytes         uint64    `json:"rx_bytes"`
	TxBytes         uint64    `json:"tx_bytes"`
	RxRateBPS       uint64    `json:"rx_rate_bps"`
	TxRateBPS       uint64    `json:"tx_rate_bps"`
	ConnectedAtUnix int64     `json:"connected_at_unix"`
	TunAttached     bool      `json:"tun_attached"`
	BypassIranLAN   bool      `json:"bypass_iran_lan"`
	LastError       *errorDTO `json:"last_error"`
}

type hostKeyPromptDTO struct {
	Host              string `json:"host"`
	Port              int    `json:"port"`
	Algorithm         string `json:"algorithm"`
	SHA256            string `json:"sha256"`
	Mismatch          bool   `json:"mismatch"`
	ExpectedAlgorithm string `json:"expected_algorithm,omitempty"`
	ExpectedSHA256    string `json:"expected_sha256,omitempty"`
}

type logEntryDTO struct {
	Timestamp  string `json:"timestamp"`
	Level      string `json:"level"`
	Message    string `json:"message"`
	Code       string `json:"code,omitempty"`
	ActionHint string `json:"action_hint,omitempty"`
}

type cidrRouteDTO struct {
	Address string `json:"address"`
	Prefix  int    `json:"prefix"`
}

type vpnPlanDTO struct {
	TunIPv4Addr   string         `json:"tun_ipv4_addr"`
	TunIPv4Prefix int            `json:"tun_ipv4_prefix"`
	TunIPv6Addr   string         `json:"tun_ipv6_addr,omitempty"`
	TunIPv6Prefix int            `json:"tun_ipv6_prefix,omitempty"`
	DNSIPv4       string         `json:"dns_ipv4"`
	MTU           int            `json:"mtu"`
	Routes        []cidrRouteDTO `json:"routes"`
}

type shareLinkMetaDTO struct {
	Version    int    `json:"version"`
	Mode       string `json:"mode"`
	HasHostKey bool   `json:"has_host_key"`
}

type shareHostKeyDTO struct {
	Alg    string `json:"alg"`
	SHA256 string `json:"sha256"`
}

type sharePayloadDTO struct {
	Name          string           `json:"name"`
	Host          string           `json:"host"`
	Port          int              `json:"port"`
	User          string           `json:"user"`
	AuthType      string           `json:"auth_type"`
	Secret        string           `json:"secret"`
	KeyPassphrase string           `json:"key_passphrase,omitempty"`
	HostKey       *shareHostKeyDTO `json:"host_key,omitempty"`
	Mode          string           `json:"mode,omitempty"`
}
