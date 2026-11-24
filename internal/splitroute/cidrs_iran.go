// Package splitroute manages split-tunnel routing tables, OS DNS configuration,
// and egress interface socket pinning for Milestone 2 TUN mode.
package splitroute

import "net/netip"

const (
	// TUNIfaceName is the canonical TUN network interface name across Linux and Windows.
	TUNIfaceName = "tunssh0"
	// TUNIPv4CIDR is the RFC 2544 benchmark IPv4 CIDR assigned to the TUN interface.
	TUNIPv4CIDR = "198.18.0.1/15"
	// TUNIPv4Addr is the local IPv4 address of the TUN interface.
	TUNIPv4Addr = "198.18.0.1"
	// TUNDNSServer is the virtual DNS interceptor address inside the TUN subnet.
	TUNDNSServer = "198.18.0.2"
	// TUNIPv6CIDR is the ULA IPv6 CIDR assigned to the TUN interface for IPv6 leak prevention.
	TUNIPv6CIDR = "fd98:18::1/64"
	// TUNMTU is the conservative TUN MTU chosen to avoid PPPoE/LTE fragmentation.
	TUNMTU = 1380

	tunIPv6Addr = "fd98:18::1"
)

// RFC1918AndLocalBypassCIDRs lists private LAN, link-local, and multicast prefixes
// that are always routed via the pre-tunnel physical gateway instead of the TUN device.
var RFC1918AndLocalBypassCIDRs = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
}

// IranBypassCIDRs is an aggregated, canonical, non-overlapping table of major Iranian IPv4
// allocations (TIC, TCI/Mokhaberat, MCI, Irancell, Shatel, ParsOnline, Asiatech, Rightel,
// MobinNet, Afranet, HiWEB, Respina, IRNIC/IPM, ArvanCloud) bypassed when BypassIranLAN is enabled.
var IranBypassCIDRs = []netip.Prefix{
	netip.MustParsePrefix("2.144.0.0/14"),
	netip.MustParsePrefix("2.176.0.0/12"),
	netip.MustParsePrefix("5.22.0.0/16"),
	netip.MustParsePrefix("5.23.112.0/20"),
	netip.MustParsePrefix("5.52.0.0/16"),
	netip.MustParsePrefix("5.56.128.0/19"),
	netip.MustParsePrefix("5.74.0.0/15"),
	netip.MustParsePrefix("5.78.0.0/16"),
	netip.MustParsePrefix("5.106.0.0/16"),
	netip.MustParsePrefix("5.112.0.0/12"),
	netip.MustParsePrefix("5.134.128.0/17"),
	netip.MustParsePrefix("5.144.48.0/20"),
	netip.MustParsePrefix("5.160.0.0/16"),
	netip.MustParsePrefix("5.190.0.0/16"),
	netip.MustParsePrefix("5.200.0.0/15"),
	netip.MustParsePrefix("5.202.0.0/16"),
	netip.MustParsePrefix("5.208.0.0/13"),
	netip.MustParsePrefix("5.232.0.0/13"),
	netip.MustParsePrefix("31.2.128.0/17"),
	netip.MustParsePrefix("31.7.64.0/19"),
	netip.MustParsePrefix("31.14.80.0/20"),
	netip.MustParsePrefix("31.24.200.0/21"),
	netip.MustParsePrefix("31.40.0.0/16"),
	netip.MustParsePrefix("31.56.0.0/14"),
	netip.MustParsePrefix("31.184.128.0/17"),
	netip.MustParsePrefix("37.32.0.0/16"),
	netip.MustParsePrefix("37.98.0.0/16"),
	netip.MustParsePrefix("37.129.0.0/16"),
	netip.MustParsePrefix("37.137.0.0/16"),
	netip.MustParsePrefix("37.152.160.0/19"),
	netip.MustParsePrefix("37.156.0.0/16"),
	netip.MustParsePrefix("37.202.0.0/16"),
	netip.MustParsePrefix("37.254.0.0/15"),
	netip.MustParsePrefix("46.32.0.0/18"),
	netip.MustParsePrefix("46.36.0.0/17"),
	netip.MustParsePrefix("46.100.0.0/15"),
	netip.MustParsePrefix("46.143.0.0/16"),
	netip.MustParsePrefix("46.164.64.0/18"),
	netip.MustParsePrefix("46.167.128.0/17"),
	netip.MustParsePrefix("46.209.0.0/16"),
	netip.MustParsePrefix("46.224.0.0/15"),
	netip.MustParsePrefix("62.60.128.0/17"),
	netip.MustParsePrefix("62.102.128.0/19"),
	netip.MustParsePrefix("62.220.120.0/21"),
	netip.MustParsePrefix("77.36.128.0/17"),
	netip.MustParsePrefix("77.42.0.0/16"),
	netip.MustParsePrefix("77.104.64.0/18"),
	netip.MustParsePrefix("77.237.64.0/18"),
	netip.MustParsePrefix("78.38.0.0/15"),
	netip.MustParsePrefix("78.157.32.0/19"),
	netip.MustParsePrefix("79.127.0.0/17"),
	netip.MustParsePrefix("79.132.192.0/19"),
	netip.MustParsePrefix("79.175.128.0/17"),
	netip.MustParsePrefix("80.191.0.0/16"),
	netip.MustParsePrefix("80.210.0.0/16"),
	netip.MustParsePrefix("81.12.0.0/16"),
	netip.MustParsePrefix("81.31.160.0/20"),
	netip.MustParsePrefix("81.91.128.0/18"),
	netip.MustParsePrefix("82.99.192.0/18"),
	netip.MustParsePrefix("82.115.0.0/19"),
	netip.MustParsePrefix("83.120.0.0/14"),
	netip.MustParsePrefix("84.241.0.0/18"),
	netip.MustParsePrefix("85.9.64.0/18"),
	netip.MustParsePrefix("85.15.0.0/18"),
	netip.MustParsePrefix("85.133.128.0/17"),
	netip.MustParsePrefix("85.185.0.0/16"),
	netip.MustParsePrefix("86.55.0.0/16"),
	netip.MustParsePrefix("86.104.0.0/16"),
	netip.MustParsePrefix("87.107.0.0/16"),
	netip.MustParsePrefix("89.144.128.0/17"),
	netip.MustParsePrefix("89.165.0.0/17"),
	netip.MustParsePrefix("89.196.0.0/14"),
	netip.MustParsePrefix("89.221.80.0/20"),
	netip.MustParsePrefix("89.235.64.0/18"),
	netip.MustParsePrefix("91.98.0.0/15"),
	netip.MustParsePrefix("91.133.128.0/17"),
	netip.MustParsePrefix("91.184.64.0/18"),
	netip.MustParsePrefix("91.251.0.0/16"),
	netip.MustParsePrefix("92.242.192.0/18"),
	netip.MustParsePrefix("93.110.0.0/16"),
	netip.MustParsePrefix("93.114.96.0/19"),
	netip.MustParsePrefix("93.118.96.0/19"),
	netip.MustParsePrefix("94.74.128.0/18"),
	netip.MustParsePrefix("94.101.176.0/20"),
	netip.MustParsePrefix("94.182.0.0/15"),
	netip.MustParsePrefix("94.184.0.0/16"),
	netip.MustParsePrefix("95.38.0.0/16"),
	netip.MustParsePrefix("95.64.0.0/17"),
	netip.MustParsePrefix("95.80.128.0/17"),
	netip.MustParsePrefix("95.82.0.0/17"),
	netip.MustParsePrefix("109.108.0.0/16"),
	netip.MustParsePrefix("109.122.192.0/18"),
	netip.MustParsePrefix("109.125.128.0/17"),
	netip.MustParsePrefix("109.162.128.0/17"),
	netip.MustParsePrefix("109.203.128.0/18"),
	netip.MustParsePrefix("109.230.64.0/18"),
	netip.MustParsePrefix("130.255.192.0/18"),
	netip.MustParsePrefix("141.11.0.0/16"),
	netip.MustParsePrefix("151.232.0.0/13"),
	netip.MustParsePrefix("151.240.0.0/13"),
	netip.MustParsePrefix("164.138.128.0/17"),
	netip.MustParsePrefix("176.46.128.0/17"),
	netip.MustParsePrefix("176.62.128.0/17"),
	netip.MustParsePrefix("176.65.192.0/18"),
	netip.MustParsePrefix("176.101.0.0/17"),
	netip.MustParsePrefix("176.221.64.0/18"),
	netip.MustParsePrefix("178.131.0.0/16"),
	netip.MustParsePrefix("178.252.128.0/18"),
	netip.MustParsePrefix("185.4.28.0/22"),
	netip.MustParsePrefix("185.8.172.0/22"),
	netip.MustParsePrefix("185.10.72.0/22"),
	netip.MustParsePrefix("185.37.52.0/22"),
	netip.MustParsePrefix("185.47.48.0/22"),
	netip.MustParsePrefix("185.51.200.0/22"),
	netip.MustParsePrefix("185.55.224.0/22"),
	netip.MustParsePrefix("185.88.152.0/22"),
	netip.MustParsePrefix("185.94.96.0/22"),
	netip.MustParsePrefix("185.98.112.0/22"),
	netip.MustParsePrefix("185.105.184.0/22"),
	netip.MustParsePrefix("185.110.188.0/22"),
	netip.MustParsePrefix("185.120.220.0/22"),
	netip.MustParsePrefix("185.126.0.0/22"),
	netip.MustParsePrefix("185.141.104.0/22"),
	netip.MustParsePrefix("185.143.232.0/22"),
	netip.MustParsePrefix("185.147.176.0/22"),
	netip.MustParsePrefix("185.158.144.0/22"),
	netip.MustParsePrefix("185.166.104.0/22"),
	netip.MustParsePrefix("185.173.104.0/22"),
	netip.MustParsePrefix("185.187.84.0/22"),
	netip.MustParsePrefix("185.192.112.0/22"),
	netip.MustParsePrefix("185.208.172.0/22"),
	netip.MustParsePrefix("185.211.56.0/22"),
	netip.MustParsePrefix("185.213.164.0/22"),
	netip.MustParsePrefix("185.217.92.0/22"),
	netip.MustParsePrefix("185.226.116.0/22"),
	netip.MustParsePrefix("185.231.180.0/22"),
	netip.MustParsePrefix("185.252.84.0/22"),
	netip.MustParsePrefix("188.158.0.0/15"),
	netip.MustParsePrefix("188.208.0.0/13"),
	netip.MustParsePrefix("188.229.0.0/16"),
	netip.MustParsePrefix("188.253.0.0/16"),
	netip.MustParsePrefix("193.151.128.0/19"),
	netip.MustParsePrefix("193.176.240.0/21"),
	netip.MustParsePrefix("194.5.172.0/22"),
	netip.MustParsePrefix("194.33.104.0/22"),
	netip.MustParsePrefix("194.225.0.0/16"),
	netip.MustParsePrefix("195.146.32.0/19"),
	netip.MustParsePrefix("195.181.64.0/19"),
	netip.MustParsePrefix("195.206.96.0/20"),
	netip.MustParsePrefix("212.16.64.0/19"),
	netip.MustParsePrefix("212.33.192.0/19"),
	netip.MustParsePrefix("212.50.224.0/19"),
	netip.MustParsePrefix("212.80.0.0/19"),
	netip.MustParsePrefix("213.108.16.0/20"),
	netip.MustParsePrefix("213.176.0.0/17"),
	netip.MustParsePrefix("213.207.192.0/18"),
	netip.MustParsePrefix("213.217.32.0/19"),
	netip.MustParsePrefix("213.233.160.0/19"),
	netip.MustParsePrefix("217.66.192.0/19"),
	netip.MustParsePrefix("217.144.128.0/20"),
	netip.MustParsePrefix("217.218.0.0/15"),
}

// IsBypassIP reports whether addr is an IPv4 address covered by RFC1918/local
// bypass routes or (when includeIran is true) IranBypassCIDRs.
func IsBypassIP(addr netip.Addr, includeIran bool) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return false
	}
	for _, prefix := range RFC1918AndLocalBypassCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	if includeIran {
		for _, prefix := range IranBypassCIDRs {
			if prefix.Contains(addr) {
				return true
			}
		}
	}
	return false
}
