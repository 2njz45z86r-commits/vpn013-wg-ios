// SPDX-License-Identifier: MIT
package r013routing

import (
	"errors"
	"net/netip"
	"sync/atomic"
)

type activeServicePolicy struct {
	mode          ServiceRoutingMode
	selection     ServiceSelection
	routes        PreparedServiceRoutes
	vaultRevision string
}

var activeService atomic.Pointer[activeServicePolicy]

// ActivateServicePolicy may be called only during tunnel startup, before
// installing any WFP or routes. The service owns an immutable policy for its
// entire lifetime, including Auto handovers.
func ActivateServicePolicy(c *ServiceCatalog, selection ServiceSelection, dns []netip.Addr) error {
	p, err := PrepareServiceRoutes(c, selection, dns)
	if err != nil {
		return err
	}
	if p == nil {
		activeService.Store(nil)
		return nil
	}
	copySelection := ServiceSelection{Mode: selection.EffectiveMode(), Only: append([]string(nil), selection.Only...), Bypass: append([]string(nil), selection.Bypass...)}
	activeService.Store(&activeServicePolicy{mode: selection.EffectiveMode(), selection: copySelection, routes: *p})
	return nil
}
func ServicePolicyMode() ServiceRoutingMode {
	p := activeService.Load()
	if p == nil {
		return ServicesUnchanged
	}
	return p.mode
}
func ServiceDirectIPv4() []netip.Prefix {
	p := activeService.Load()
	if p == nil {
		return nil
	}
	return append([]netip.Prefix(nil), p.routes.DirectIPv4...)
}
func Effective(original netip.Prefix) ([]netip.Prefix, error) {
	if !Enabled() {
		return []netip.Prefix{original.Masked()}, nil
	}
	p := activeService.Load()
	if p == nil || original.Addr().Is6() {
		return Exclude(original)
	}
	if !original.IsValid() || !original.Addr().Is4() || original.Masked() != netip.MustParsePrefix("0.0.0.0/0") {
		return nil, errors.New("Для режима сервисов требуется один полный IPv4 маршрут.")
	}
	return append([]netip.Prefix(nil), p.routes.TunnelIPv4...), nil
}
