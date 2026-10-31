// SPDX-License-Identifier: MIT
package r013routing

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func servicePrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func serviceContains(ps []netip.Prefix, s string) bool {
	a := netip.MustParseAddr(s)
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
func TestServiceRoutesOnlyAndOffPreserveBaseline(t *testing.T) {
	baseline := []netip.Prefix{servicePrefix("0.0.0.0/0"), servicePrefix("2000::/3")}
	saved := append([]netip.Prefix(nil), baseline...)
	off, err := BuildServiceRoutes(baseline, nil)
	if err != nil || !reflect.DeepEqual(off, baseline) {
		t.Fatal("off changed baseline")
	}
	off[0] = servicePrefix("1.1.1.1/32")
	if !reflect.DeepEqual(baseline, saved) {
		t.Fatal("off aliases baseline")
	}
	p := &ServiceRoutePlan{Mode: ServicesOnly, Networks: []netip.Prefix{servicePrefix("8.8.8.0/24")}}
	routes, err := BuildServiceRoutes(baseline, p)
	if err != nil || !serviceContains(routes, "8.8.8.8") || serviceContains(routes, "1.1.1.1") || !serviceContains(routes, "2606:4700::1") || !reflect.DeepEqual(baseline, saved) {
		t.Fatal("only routes or IPv6 policy changed incorrectly", err)
	}
}
func TestServiceRoutesBypassSubtractsOnlyFromBaseline(t *testing.T) {
	baseline := []netip.Prefix{servicePrefix("0.0.0.0/1"), servicePrefix("2000::/3")}
	p := &ServiceRoutePlan{Mode: ServicesBypass, Networks: []netip.Prefix{servicePrefix("8.8.8.0/24"), servicePrefix("8.8.8.0/25"), servicePrefix("192.0.2.0/24")}}
	routes, err := BuildServiceRoutes(baseline, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"8.8.8.8", "192.0.2.1"} {
		if serviceContains(routes, s) {
			t.Fatal("excluded or outside baseline", s)
		}
	}
	for _, s := range []string{"8.8.7.255", "8.8.9.0", "1.1.1.1", "2606:4700::1"} {
		if !serviceContains(routes, s) {
			t.Fatal("lost baseline", s)
		}
	}
}
func TestServiceRoutesRejectUnsupportedAndInvalid(t *testing.T) {
	baseline := []netip.Prefix{servicePrefix("0.0.0.0/0")}
	for _, p := range []*ServiceRoutePlan{{Mode: ServicesOnly, Networks: []netip.Prefix{servicePrefix("8.8.8.0/24")}, Domains: []string{"example.invalid"}}, {Mode: ServicesOnly}, {Mode: ServicesBypass, Networks: []netip.Prefix{servicePrefix("::/0")}}, {Mode: "bad", Networks: []netip.Prefix{servicePrefix("8.8.8.0/24")}}} {
		if _, err := BuildServiceRoutes(baseline, p); err == nil {
			t.Fatal("unsupported plan accepted")
		}
	}
}

func TestOwnerCatalogIPv4BypassFailsClosedAtRouteLimit(t *testing.T) {
	dir := os.Getenv("VPN013_ROUTING_CATALOG_TEST_DIR")
	if dir == "" {
		t.Skip("owner resources provided separately")
	}
	ui, err := os.ReadFile(filepath.Join(dir, "catalog-ui.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := os.ReadFile(filepath.Join(dir, "catalog-rules.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeServiceCatalog(ui, rules)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, s := range c.DisplayServices() {
		p, e := c.Resolve(ServiceSelection{Mode: ServicesBypass, Bypass: []string{s.ID}})
		if e != nil {
			t.Fatal(e)
		}
		if len(p.Domains) == 0 {
			ids = append(ids, s.ID)
		}
	}
	p, err := c.Resolve(ServiceSelection{Mode: ServicesBypass, Bypass: ids})
	if err != nil {
		t.Fatal(err)
	}
	base, err := Exclude(servicePrefix("0.0.0.0/0"))
	if err != nil {
		t.Fatal(err)
	}
	routes, err := BuildServiceRoutes(base, p)
	if err == nil || err.Error() != "service route limit" || len(routes) != 0 {
		t.Fatal("oversized selection must fail without a partial route result")
	}
}

func TestOwnerGroupsMatchPinnedDisplay(t *testing.T) {
	dir := os.Getenv("VPN013_ROUTING_CATALOG_TEST_DIR")
	if dir == "" {
		t.Skip("owner resources provided separately")
	}
	data, err := os.ReadFile(filepath.Join(dir, "catalog-groups.json"))
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(data)) != "a88d52da61ab4e596bb6050843bf11619148de40235a00a8162c660aba1ab882" {
		t.Fatal("groups hash mismatch")
	}
	ui, err := os.ReadFile(filepath.Join(dir, "catalog-ui.json"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := os.ReadFile(filepath.Join(dir, "catalog-rules.private.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeServiceCatalog(ui, rules)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Groups []CatalogGroup `json:"groups"`
	}
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	got := c.DisplayGroups("")
	if !reflect.DeepEqual(got, fixture.Groups) {
		t.Fatal("display groups differ from pinned owner groups")
	}
}
