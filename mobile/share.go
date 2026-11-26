package mobile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/AlirezaDelkhahi/tunssh/internal/crypto"
	"github.com/AlirezaDelkhahi/tunssh/internal/splitroute"
)

// InspectShareLink inspects an sshtun://v1/ envelope without decrypting its payload
// and returns a JSON-encoded share-link metadata object.
func InspectShareLink(link string) (string, error) {
	meta, err := crypto.InspectShareLink(strings.TrimSpace(link))
	if err != nil {
		return "", err
	}
	dto := shareLinkMetaDTO{
		Version:    meta.Version,
		Mode:       meta.Mode,
		HasHostKey: meta.HasHostKey,
	}
	b, err := json.Marshal(dto)
	if err != nil {
		return "", fmt.Errorf("mobile: marshal share link metadata: %w", err)
	}
	return string(b), nil
}

// DecodeShareLink parses, validates, and optionally decrypts an sshtun://v1/ share link,
// returning a JSON-encoded share payload object with mode populated.
func DecodeShareLink(link, passphrase string, allowPlain bool) (string, error) {
	payload, mode, err := crypto.DecodeShareLink(strings.TrimSpace(link), crypto.DecodeOptions{
		Passphrase:       passphrase,
		AllowPlainImport: allowPlain,
	})
	if err != nil {
		return "", err
	}
	dto := sharePayloadDTO{
		Name:          payload.Name,
		Host:          payload.Host,
		Port:          payload.Port,
		User:          payload.User,
		AuthType:      payload.AuthType,
		Secret:        payload.Secret,
		KeyPassphrase: payload.KeyPassphrase,
		Mode:          mode,
	}
	if payload.HostKey != nil {
		dto.HostKey = &shareHostKeyDTO{
			Alg:    payload.HostKey.Alg,
			SHA256: payload.HostKey.SHA256,
		}
	}
	b, err := json.Marshal(dto)
	if err != nil {
		return "", fmt.Errorf("mobile: marshal share payload: %w", err)
	}
	return string(b), nil
}

// EncodeShareLink encodes a JSON share payload object into an sshtun://v1/ share link.
// Links are encrypted with passphrase unless passphrase is empty and allowPlain is true.
func EncodeShareLink(payloadJSON, passphrase string, allowPlain bool) (string, error) {
	var dto sharePayloadDTO
	if err := json.Unmarshal([]byte(payloadJSON), &dto); err != nil {
		return "", fmt.Errorf("mobile: invalid share payload JSON: %w", err)
	}
	payload := crypto.SharePayload{
		Name:          dto.Name,
		Host:          dto.Host,
		Port:          dto.Port,
		User:          dto.User,
		AuthType:      dto.AuthType,
		Secret:        dto.Secret,
		KeyPassphrase: dto.KeyPassphrase,
	}
	if dto.HostKey != nil {
		payload.HostKey = &crypto.ShareHostKey{
			Alg:    dto.HostKey.Alg,
			SHA256: dto.HostKey.SHA256,
		}
	}

	if passphrase != "" {
		return crypto.EncodeEncryptedShareLink(payload, passphrase)
	}
	if allowPlain {
		return crypto.EncodePlainShareLink(payload, true)
	}
	return "", crypto.ErrPlainShareNotAllowed
}

// BuildVpnPlan computes the Android VpnService.Builder interface, DNS, MTU, and split-route
// complement plan and returns it as a JSON-encoded VPN plan object.
func BuildVpnPlan(bypassIranLan bool, enableIPv6 bool, mtu int32) (string, error) {
	effectiveMTU := int(mtu)
	if effectiveMTU <= 0 {
		effectiveMTU = splitroute.TUNMTU
	}

	tun4, err := netip.ParsePrefix(splitroute.TUNIPv4CIDR)
	if err != nil {
		return "", fmt.Errorf("mobile: parse TUN IPv4 CIDR: %w", err)
	}

	includedV4 := splitroute.ComputeIncludedIPv4CIDRs(splitroute.ExcludedIPv4Prefixes(bypassIranLan))
	extraV6 := 0
	if enableIPv6 {
		extraV6 = 2
	}
	routes := make([]cidrRouteDTO, 0, len(includedV4)+extraV6)
	for _, p := range includedV4 {
		routes = append(routes, cidrRouteDTO{
			Address: p.Addr().String(),
			Prefix:  p.Bits(),
		})
	}

	plan := vpnPlanDTO{
		TunIPv4Addr:   tun4.Addr().String(),
		TunIPv4Prefix: tun4.Bits(),
		DNSIPv4:       splitroute.TUNDNSServer,
		MTU:           effectiveMTU,
		Routes:        routes,
	}

	if enableIPv6 {
		tun6, err := netip.ParsePrefix(splitroute.TUNIPv6CIDR)
		if err != nil {
			return "", fmt.Errorf("mobile: parse TUN IPv6 CIDR: %w", err)
		}
		plan.TunIPv6Addr = tun6.Addr().String()
		plan.TunIPv6Prefix = tun6.Bits()
		plan.Routes = append(plan.Routes,
			cidrRouteDTO{Address: "::", Prefix: 1},
			cidrRouteDTO{Address: "8000::", Prefix: 1},
		)
	}

	b, err := json.Marshal(plan)
	if err != nil {
		return "", fmt.Errorf("mobile: marshal VPN plan: %w", err)
	}
	return string(b), nil
}
