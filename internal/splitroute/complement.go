package splitroute

import (
	"encoding/binary"
	"net/netip"
	"slices"
)

type ipv4Interval struct {
	start uint64
	end   uint64
}

var (
	v4UnspecifiedPrefix = netip.MustParsePrefix("0.0.0.0/8")
	v4LoopbackPrefix    = netip.MustParsePrefix("127.0.0.0/8")
	v4ReservedPrefix    = netip.MustParsePrefix("240.0.0.0/4")
)

// ExcludedIPv4Prefixes returns the canonical list of IPv4 prefixes that should
// be excluded from VPN TUN capture (e.g., passed to complement calculation for Android
// VpnService.Builder.addRoute).
func ExcludedIPv4Prefixes(bypassIranLAN bool) []netip.Prefix {
	extra := 0
	if bypassIranLAN {
		extra = len(IranBypassCIDRs)
	}
	out := make([]netip.Prefix, 0, 3+len(RFC1918AndLocalBypassCIDRs)+extra)
	out = append(out, v4UnspecifiedPrefix, v4LoopbackPrefix)
	out = append(out, RFC1918AndLocalBypassCIDRs...)
	out = append(out, v4ReservedPrefix)
	if bypassIranLAN {
		out = append(out, IranBypassCIDRs...)
	}
	return out
}

// ComputeIncludedIPv4CIDRs subtracts all valid IPv4 prefixes in exclude from 0.0.0.0/0
// and returns a sorted, minimal, canonical, non-overlapping slice of included IPv4 prefixes.
func ComputeIncludedIPv4CIDRs(exclude []netip.Prefix) []netip.Prefix {
	merged := mergeExcludedIPv4Intervals(exclude)
	if len(merged) == 1 && merged[0].start == 0 && merged[0].end == 0xFFFFFFFF {
		return nil
	}
	if len(merged) == 0 {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	}

	var out []netip.Prefix
	splitIncludedV4(0, 0, merged, &out)
	return out
}

func mergeExcludedIPv4Intervals(exclude []netip.Prefix) []ipv4Interval {
	intervals := make([]ipv4Interval, 0, len(exclude))
	for _, p := range exclude {
		if !p.IsValid() || !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		b := p.Addr().As4()
		start := uint64(binary.BigEndian.Uint32(b[:]))
		size := uint64(1) << (32 - p.Bits())
		intervals = append(intervals, ipv4Interval{
			start: start,
			end:   start + size - 1,
		})
	}
	if len(intervals) == 0 {
		return nil
	}

	slices.SortFunc(intervals, func(a, b ipv4Interval) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		if a.end < b.end {
			return -1
		}
		if a.end > b.end {
			return 1
		}
		return 0
	})

	merged := make([]ipv4Interval, 0, len(intervals))
	cur := intervals[0]
	for _, iv := range intervals[1:] {
		if iv.start <= cur.end+1 {
			if iv.end > cur.end {
				cur.end = iv.end
			}
			continue
		}
		merged = append(merged, cur)
		cur = iv
	}
	merged = append(merged, cur)
	return merged
}

func splitIncludedV4(candStart uint64, prefixLen int, excluded []ipv4Interval, out *[]netip.Prefix) {
	size := uint64(1) << (32 - prefixLen)
	candEnd := candStart + size - 1

	// Find first excluded interval whose end >= candStart.
	idx, _ := slices.BinarySearchFunc(excluded, candStart, func(iv ipv4Interval, target uint64) int {
		if iv.end < target {
			return -1
		}
		return 1
	})

	if idx >= len(excluded) || excluded[idx].start > candEnd {
		// Completely disjoint from all excluded intervals.
		*out = append(*out, prefixFromU32(uint32(candStart), prefixLen))
		return
	}

	if excluded[idx].start <= candStart && excluded[idx].end >= candEnd {
		// Completely contained in an excluded interval.
		return
	}

	// Partially overlaps at least one excluded interval; split into /prefixLen+1 halves.
	half := size >> 1
	splitIncludedV4(candStart, prefixLen+1, excluded, out)
	splitIncludedV4(candStart+half, prefixLen+1, excluded, out)
}

func prefixFromU32(addr uint32, bits int) netip.Prefix {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], addr)
	return netip.PrefixFrom(netip.AddrFrom4(b), bits)
}
