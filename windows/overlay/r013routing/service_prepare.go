// SPDX-License-Identifier: MIT
package r013routing

import (
	"errors"
	"net/netip"
)

// PreparedServiceRoutes is an inert preflight result. A tunnel service must
// install BOTH route and WFP policy, verify readback and own cleanup before
// reporting success. IPv6 continues using the existing policy.
type PreparedServiceRoutes struct {
	TunnelIPv4 []netip.Prefix
	DirectIPv4 []netip.Prefix
}

// PrepareServiceRoutes validates active IPv4 routing and bounded WFP inputs.
// DNS servers are explicit, IP-only and remain routed through the tunnel in
// ONLY mode. BYPASS never knowingly directs configured DNS outside the VPN.
func PrepareServiceRoutes(c *ServiceCatalog, selection ServiceSelection, dns []netip.Addr) (*PreparedServiceRoutes, error) {
	plan, err := c.Resolve(selection)
	if err != nil || plan == nil {
		return nil, err
	}
	if len(plan.Domains) > 0 {
		return nil, errors.New("Маршрутизация выбранного сервиса по доменам недоступна для WireGuard.")
	}
	if len(dns) == 0 || len(dns) > 64 {
		return nil, errors.New("Для этого режима нужен IPv4 DNS в профиле.")
	}
	for _, a := range dns {
		if !a.IsValid() || !a.Is4() || a.IsUnspecified() {
			return nil, errors.New("Для этого режима нужен IPv4 DNS в профиле.")
		}
	}
	baseline, err := Exclude(netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil {
		return nil, err
	}
	p := *plan
	p.Networks = append([]netip.Prefix(nil), plan.Networks...)
	if plan.Mode == ServicesOnly {
		for _, a := range dns {
			p.Networks = append(p.Networks, netip.PrefixFrom(a, 32))
		}
	} else {
		for _, a := range dns {
			for _, n := range p.Networks {
				if n.Contains(a) {
					return nil, errors.New("Выбранный обход включает DNS профиля. Выберите другой сервис или DNS.")
				}
			}
		}
	}
	tunnel, err := BuildServiceRoutes(baseline, &p)
	if err != nil {
		return nil, err
	}
	var direct []netip.Prefix
	if plan.Mode == ServicesOnly {
		// Direct WFP destinations are exactly the IPv4 complement of the selected
		// tunnel destinations, including the explicit DNS host routes.
		bypass := p
		bypass.Mode = ServicesBypass
		direct, err = BuildServiceRoutes([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, &bypass)
	} else {
		direct = append([]netip.Prefix(nil), p.Networks...)
	}
	if err != nil {
		return nil, err
	}
	if len(tunnel) > 40000 || len(direct) > 40000 {
		return nil, errors.New("Слишком много маршрутов. Уменьшите число выбранных сервисов.")
	}
	return &PreparedServiceRoutes{tunnel, direct}, nil
}
