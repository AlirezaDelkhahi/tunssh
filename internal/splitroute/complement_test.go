package splitroute

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func ipv4ToU32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

func prefixBoundsU32(p netip.Prefix) (uint32, uint32) {
	p = p.Masked()
	start := ipv4ToU32(p.Addr())
	size := uint64(1) << (32 - p.Bits())
	end := uint32(uint64(start) + size - 1)
	return start, end
}

func countPrefixMatches(prefixes []netip.Prefix, ip netip.Addr) int {
	n := 0
	for _, p := range prefixes {
		if p.Contains(ip) {
			n++
		}
	}
	return n
}

func assertValidMinimalSortedV4Prefixes(t *testing.T, prefixes []netip.Prefix) {
	t.Helper()
	for i, p := range prefixes {
		if !p.IsValid() || !p.Addr().Is4() {
			t.Fatalf("prefix[%d] = %v is not a valid IPv4 prefix", i, p)
		}
		if p != p.Masked() {
			t.Fatalf("prefix[%d] = %v is not canonical/masked (%v)", i, p, p.Masked())
		}
		if i > 0 {
			prevStart, prevEnd := prefixBoundsU32(prefixes[i-1])
			curStart, _ := prefixBoundsU32(p)
			if curStart <= prevEnd {
				t.Fatalf("prefixes[%d]=%v (%08x) overlaps or is unsorted relative to prefixes[%d]=%v (%08x..%08x)",
					i, p, curStart, i-1, prefixes[i-1], prevStart, prevEnd)
			}
			// Check minimality: adjacent siblings of identical prefix length must not be mergeable.
			if prefixes[i-1].Bits() == p.Bits() && prevEnd+1 == curStart {
				bits := p.Bits()
				if bits > 0 {
					siblingMask := uint32(1) << (32 - bits)
					if (prevStart & siblingMask) == 0 {
						t.Fatalf("prefixes[%d]=%v and prefixes[%d]=%v are mergeable adjacent siblings", i-1, prefixes[i-1], i, p)
					}
				}
			}
		}
	}
}

func TestComputeIncludedIPv4CIDRs_InvariantsAndExclusions(t *testing.T) {
	for _, bypassIran := range []bool{false, true} {
		excluded := ExcludedIPv4Prefixes(bypassIran)
		included := ComputeIncludedIPv4CIDRs(excluded)
		if len(included) == 0 {
			t.Fatalf("ComputeIncludedIPv4CIDRs(bypassIran=%v) returned empty slice", bypassIran)
		}
		assertValidMinimalSortedV4Prefixes(t, included)

		alwaysExcluded := []string{
			"0.0.0.1",
			"10.1.2.3",
			"127.0.0.1",
			"169.254.1.1",
			"172.16.0.1",
			"192.168.1.1",
			"224.0.0.1",
			"255.255.255.255",
		}
		for _, ipStr := range alwaysExcluded {
			ip := netip.MustParseAddr(ipStr)
			if matches := countPrefixMatches(included, ip); matches != 0 {
				t.Fatalf("bypassIran=%v: expected %s to be excluded, matched %d prefixes", bypassIran, ipStr, matches)
			}
		}

		alwaysIncluded := []string{
			"198.18.0.1",
			"198.18.0.2",
			"1.1.1.1",
			"8.8.8.8",
			"140.82.121.4",
		}
		for _, ipStr := range alwaysIncluded {
			ip := netip.MustParseAddr(ipStr)
			if matches := countPrefixMatches(included, ip); matches != 1 {
				t.Fatalf("bypassIran=%v: expected %s to be included by exact 1 prefix, got %d", bypassIran, ipStr, matches)
			}
		}
	}

	// Verify IranBypassCIDRs are excluded when bypassIranLAN=true.
	includedWithIranBypass := ComputeIncludedIPv4CIDRs(ExcludedIPv4Prefixes(true))
	if len(IranBypassCIDRs) < 3 {
		t.Fatalf("unexpectedly small IranBypassCIDRs: %d", len(IranBypassCIDRs))
	}
	iranSamples := []netip.Prefix{
		IranBypassCIDRs[0],
		IranBypassCIDRs[len(IranBypassCIDRs)/2],
		IranBypassCIDRs[len(IranBypassCIDRs)-1],
	}
	for _, p := range iranSamples {
		ip := p.Masked().Addr()
		if matches := countPrefixMatches(includedWithIranBypass, ip); matches != 0 {
			t.Fatalf("bypassIran=true: expected Iran CIDR sample %s (%s) to be excluded, matched %d prefixes", p, ip, matches)
		}
	}

	// Verify a global Iranian IP is included when bypassIranLAN=false.
	includedWithoutIranBypass := ComputeIncludedIPv4CIDRs(ExcludedIPv4Prefixes(false))
	iranGlobalIP := netip.MustParseAddr("2.144.0.1")
	if matches := countPrefixMatches(includedWithoutIranBypass, iranGlobalIP); matches != 1 {
		t.Fatalf("bypassIran=false: expected %s to be included by exact 1 prefix, got %d", iranGlobalIP, matches)
	}
}

func TestComputeIncludedIPv4CIDRs_EdgeCases(t *testing.T) {
	// Empty exclude -> 0.0.0.0/0
	all := ComputeIncludedIPv4CIDRs(nil)
	if len(all) != 1 || all[0] != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("ComputeIncludedIPv4CIDRs(nil) = %v, want [0.0.0.0/0]", all)
	}

	// Adjacent + overlapping + unmasked + IPv6 inputs should normalize cleanly.
	inc := ComputeIncludedIPv4CIDRs([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.5/1"),
		netip.MustParsePrefix("128.0.0.0/2"),
		netip.MustParsePrefix("192.0.0.1/2"),
		netip.MustParsePrefix("fd98:18::/64"),
	})
	if len(inc) != 0 {
		t.Fatalf("expected full IPv4 exclusion to return empty slice, got %v", inc)
	}

	// Adjacent sibling excluded prefixes (128.0.0.0/2 + 192.0.0.0/2 == 128.0.0.0/1) -> only 0.0.0.0/1 included.
	half := ComputeIncludedIPv4CIDRs([]netip.Prefix{
		netip.MustParsePrefix("128.0.0.0/2"),
		netip.MustParsePrefix("192.0.0.0/2"),
	})
	if len(half) != 1 || half[0] != netip.MustParsePrefix("0.0.0.0/1") {
		t.Fatalf("got %v, want [0.0.0.0/1]", half)
	}
}
