// SPDX-License-Identifier: MIT
package r013routing

import (
	"errors"
	"net/netip"
	"sort"
)

// BuildServiceRoutes computes route destinations only; it does not apply routes,
// configure firewall exceptions, persist selections, or modify peer AllowedIPs.
// baseline is the actual existing OS-route policy for a supported full IPv4
// profile, including any IPv6 routes. Callers must separately ensure DNS,
// control endpoints, ownership, firewall, and lifecycle safety.
func BuildServiceRoutes(baseline []netip.Prefix, plan *ServiceRoutePlan) ([]netip.Prefix, error) {
	if len(baseline) > 40000 {
		return nil, errors.New("baseline route limit")
	}
	for _, p := range baseline {
		if !p.IsValid() || p != p.Masked() {
			return nil, errors.New("invalid baseline route")
		}
	}
	if plan == nil {
		return append([]netip.Prefix(nil), baseline...), nil
	}
	if plan.Mode != ServicesOnly && plan.Mode != ServicesBypass {
		return nil, errors.New("invalid service mode")
	}
	if len(plan.Domains) != 0 {
		return nil, errors.New("domain routing is unavailable for WireGuard")
	}
	if len(plan.Networks) == 0 || len(plan.Networks) > 16384 {
		return nil, errors.New("service network limit")
	}
	for _, p := range plan.Networks {
		if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || p.Bits() == 0 {
			return nil, errors.New("invalid service network")
		}
	}
	out := make([]netip.Prefix, 0, len(baseline))
	if plan.Mode == ServicesOnly {
		// Do not silently remove or change the profile's IPv6 policy.
		for _, p := range baseline {
			if p.Addr().Is6() {
				out = append(out, p)
			}
		}
		out = append(out, plan.Networks...)
		return out, nil
	}
	// Bypass subtracts selected networks from the existing OS policy, never
	// creating a new tunnel route outside the existing baseline.
	selected := append([]netip.Prefix(nil), plan.Networks...)
	sort.Slice(selected, func(i, j int) bool {
		a, b := selected[i], selected[j]
		if a.Addr() != b.Addr() {
			return a.Addr().Less(b.Addr())
		}
		return a.Bits() < b.Bits()
	})
	disjoint := selected[:0]
	for _, p := range selected {
		if len(disjoint) > 0 && disjoint[len(disjoint)-1].Contains(p.Addr()) {
			continue
		}
		disjoint = append(disjoint, p)
	}
	budget := 2000000
	var subtract func(netip.Prefix, []netip.Prefix) error
	subtract = func(p netip.Prefix, candidates []netip.Prefix) error {
		budget--
		if budget < 0 {
			return errors.New("service route computation limit")
		}
		overlaps := make([]netip.Prefix, 0, len(candidates))
		for _, n := range candidates {
			budget--
			if budget < 0 {
				return errors.New("service route computation limit")
			}
			if !p.Overlaps(n) {
				continue
			}
			if n.Bits() <= p.Bits() && n.Contains(p.Addr()) {
				return nil
			}
			overlaps = append(overlaps, n)
		}
		if len(overlaps) == 0 {
			out = append(out, p)
			if len(out) > 40000 {
				return errors.New("service route limit")
			}
			return nil
		}
		bits := p.Bits() + 1
		left := netip.PrefixFrom(p.Addr(), bits)
		raw := p.Addr().As4()
		raw[(bits-1)/8] |= 1 << uint(7-(bits-1)%8)
		right := netip.PrefixFrom(netip.AddrFrom4(raw), bits)
		if err := subtract(left, overlaps); err != nil {
			return err
		}
		return subtract(right, overlaps)
	}
	for _, p := range baseline {
		if p.Addr().Is6() {
			out = append(out, p)
			continue
		}
		start := sort.Search(len(disjoint), func(i int) bool { return disjoint[i].Addr().Compare(p.Addr()) >= 0 })
		if start > 0 && disjoint[start-1].Contains(p.Addr()) {
			start--
		}
		end := start
		for end < len(disjoint) && disjoint[end].Overlaps(p) {
			end++
		}
		if err := subtract(p, disjoint[start:end]); err != nil {
			return nil, err
		}
	}
	if len(out) > 40000 {
		return nil, errors.New("service route limit")
	}
	return out, nil
}
