// SPDX-License-Identifier: MIT
package r013routing

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestServicePreflightDNSAndDirectCoverage(t *testing.T) {
	c := catalogFixture(t)
	dns := []netip.Addr{netip.MustParseAddr("9.9.9.9")}
	p, err := PrepareServiceRoutes(c, ServiceSelection{Mode: ServicesOnly, Only: []string{serviceB}}, dns)
	if err != nil {
		t.Fatal(err)
	}
	if !serviceContains(p.TunnelIPv4, "1.1.1.1") || !serviceContains(p.TunnelIPv4, "9.9.9.9") || serviceContains(p.DirectIPv4, "1.1.1.1") || serviceContains(p.DirectIPv4, "9.9.9.9") || !serviceContains(p.DirectIPv4, "4.4.4.4") {
		t.Fatal("inconsistent tunnel/direct/DNS coverage")
	}
	b, err := PrepareServiceRoutes(c, ServiceSelection{Mode: ServicesBypass, Bypass: []string{serviceB}}, dns)
	if err != nil {
		t.Fatal(err)
	}
	if serviceContains(b.TunnelIPv4, "1.1.1.1") || !serviceContains(b.DirectIPv4, "1.1.1.1") || !serviceContains(b.TunnelIPv4, "9.9.9.9") {
		t.Fatal("bypass coverage or DNS incorrect")
	}
}
func TestServicePreflightRejectsDomainAndDNSBypass(t *testing.T) {
	c := catalogFixture(t)
	for _, tc := range []struct {
		s   ServiceSelection
		dns []netip.Addr
	}{{ServiceSelection{Mode: ServicesOnly, Only: []string{serviceA}}, []netip.Addr{netip.MustParseAddr("9.9.9.9")}}, {ServiceSelection{Mode: ServicesBypass, Bypass: []string{serviceB}}, []netip.Addr{netip.MustParseAddr("1.1.1.1")}}, {ServiceSelection{Mode: ServicesOnly, Only: []string{serviceB}}, nil}} {
		if _, err := PrepareServiceRoutes(c, tc.s, tc.dns); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	p, err := PrepareServiceRoutes(c, ServiceSelection{}, nil)
	if err != nil || p != nil {
		t.Fatal("off changed legacy policy")
	}
}

func TestServiceRuntimeEffectiveRouting(t *testing.T) {
	before := active.Load()
	defer active.Store(before)
	defer activeService.Store(nil)
	Enable()
	cat := catalogFixture(t)
	sel := ServiceSelection{Mode: ServicesOnly, Only: []string{serviceB}}
	if err := ActivateServicePolicy(cat, sel, []netip.Addr{netip.MustParseAddr("9.9.9.9")}); err != nil {
		t.Fatal(err)
	}
	routes, err := Effective(netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil || !serviceContains(routes, "1.1.1.1") || serviceContains(routes, "4.4.4.4") || !serviceContains(ServiceDirectIPv4(), "4.4.4.4") {
		t.Fatal("service routes not active", err)
	}
	if _, err = Effective(netip.MustParsePrefix("10.0.0.0/8")); err == nil {
		t.Fatal("unsupported partial profile accepted")
	}
	v6, err := Effective(netip.MustParsePrefix("2001:4860::/32"))
	if err != nil || !serviceContains(v6, "2001:4860::1") {
		t.Fatal("IPv6 policy not preserved", err)
	}
	if err = ActivateServicePolicy(cat, ServiceSelection{}, nil); err != nil {
		t.Fatal(err)
	}
	off, err := Effective(netip.MustParsePrefix("0.0.0.0/0"))
	baseline, e := Exclude(netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil || e != nil || !reflect.DeepEqual(off, baseline) || len(ServiceDirectIPv4()) != 0 {
		t.Fatal("off did not restore baseline")
	}
}
