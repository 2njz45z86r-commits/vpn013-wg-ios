// SPDX-License-Identifier: MIT
package r013routing

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const serviceA = "svc_0000000000000001"
const serviceB = "svc_0000000000000002"

func catalogFixture(t *testing.T) *ServiceCatalog {
	t.Helper()
	ui := []byte(`{"version":1,"defaults":{"mode":"unchanged","onlySelectedIds":[],"bypassSelectedIds":[]},"modes":["unchanged","only_selected","bypass_selected"],"mutuallyExclusiveSwitches":true,"services":[{"id":"svc_0000000000000001","name":"Alpha","icon":{"kind":"monogram","text":"A"},"category":"Examples","archivedOnly":false},{"id":"svc_0000000000000002","name":"Beta","icon":{"kind":"monogram","text":"B"},"category":"Examples","archivedOnly":false}]}`)
	rules := []byte(`{"version":1,"services":{"svc_0000000000000001":{"ipv4":["8.8.8.0/24"],"domains":["alpha.example.invalid"]},"svc_0000000000000002":{"ipv4":["8.8.8.0/24","1.1.1.0/24"],"domains":[]}}}`)
	c, err := decodeServiceCatalog(ui, rules, fmt.Sprintf("%x", sha256.Sum256(ui)), fmt.Sprintf("%x", sha256.Sum256(rules)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogBothSwitchesOffPreservesExistingPolicy(t *testing.T) {
	c := catalogFixture(t)
	for _, selection := range []ServiceSelection{{}, {Mode: ServicesUnchanged}, {Only: []string{serviceA}, Bypass: []string{serviceB}}} {
		before := Enabled()
		plan, err := c.Resolve(selection)
		if err != nil || plan != nil || Enabled() != before {
			t.Fatal("opening catalog changed existing policy")
		}
	}
}

func TestCatalogSwitchesAreExclusiveAndRetainChoices(t *testing.T) {
	s := ServiceSelection{Only: []string{serviceA}, Bypass: []string{serviceB}}
	s.SetOnly(true)
	if s.EffectiveMode() != ServicesOnly {
		t.Fatal("only not enabled")
	}
	s.SetBypass(true)
	if s.EffectiveMode() != ServicesBypass {
		t.Fatal("opposite switch remained on")
	}
	s.SetOnly(false)
	if s.EffectiveMode() != ServicesBypass {
		t.Fatal("inactive switch changed active mode")
	}
	s.SetBypass(false)
	if s.EffectiveMode() != ServicesUnchanged {
		t.Fatal("both off did not restore previous policy")
	}
	if !reflect.DeepEqual(s.Only, []string{serviceA}) || !reflect.DeepEqual(s.Bypass, []string{serviceB}) {
		t.Fatal("choices discarded")
	}
}

func TestCatalogOnlyExplicitSelectionsResolve(t *testing.T) {
	c := catalogFixture(t)
	for _, mode := range []ServiceRoutingMode{ServicesOnly, ServicesBypass} {
		if _, err := c.Resolve(ServiceSelection{Mode: mode}); err == nil {
			t.Fatal("empty active mode accepted")
		}
	}
	s := ServiceSelection{Mode: ServicesOnly, Only: []string{serviceA}, Bypass: []string{serviceB}}
	p, err := c.Resolve(s)
	if err != nil || p.Mode != ServicesOnly || len(p.Networks) != 1 || len(p.Domains) != 1 {
		t.Fatal("selected service not isolated")
	}
	s.SetBypass(true)
	p, err = c.Resolve(s)
	if err != nil || p.Mode != ServicesBypass || len(p.Networks) != 2 || len(p.Domains) != 0 {
		t.Fatal("inactive selection applied")
	}
	s.SetOnly(true)
	s.Only = []string{serviceB, serviceA}
	p, err = c.Resolve(s)
	if err != nil || len(p.Networks) != 2 || p.Networks[0].String() != "1.1.1.0/24" {
		t.Fatal("plan not deduplicated and deterministic")
	}
}

func TestCatalogRejectsUnknownDuplicateAndInvalidMode(t *testing.T) {
	c := catalogFixture(t)
	for _, s := range []ServiceSelection{
		{Mode: "both", Only: []string{serviceA}},
		{Mode: ServicesOnly, Only: []string{"svc_0000000000000003"}},
		{Mode: ServicesOnly, Only: []string{serviceA, serviceA}},
		{Mode: ServicesBypass, Bypass: []string{serviceB}, Only: []string{"vless://not-a-service"}},
	} {
		if _, err := c.Resolve(s); err == nil {
			t.Fatal("untrusted selection accepted")
		}
	}
	if _, err := DecodeServiceCatalog([]byte(`{}`), []byte(`{}`)); err == nil {
		t.Fatal("unpinned resources accepted")
	}
}

func TestCatalogDisplayDoesNotExposeOrAliasRules(t *testing.T) {
	c := catalogFixture(t)
	display := c.DisplayServices()
	display[0].Name = "Changed"
	if c.DisplayServices()[0].Name != "Alpha" {
		t.Fatal("display alias mutated catalog")
	}
	data, err := json.Marshal(c.DisplayServices())
	if err != nil {
		t.Fatal(err)
	}
	var decoded []map[string]any
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, row := range decoded {
		for _, key := range []string{"ipv4", "domains", "networks", "url", "command"} {
			if _, ok := row[key]; ok {
				t.Fatal("technical rule exposed in display data")
			}
		}
	}
}

func TestOwnerCatalogPinnedResourcesAndNoAutomaticSelection(t *testing.T) {
	dir := os.Getenv("VPN013_ROUTING_CATALOG_TEST_DIR")
	if dir == "" {
		t.Skip("owner resources provided separately from public source")
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
	if len(c.DisplayServices()) != 412 {
		t.Fatal("owner list incomplete")
	}
	p, err := c.Resolve(ServiceSelection{})
	if err != nil || p != nil {
		t.Fatal("owner defaults changed routing")
	}
	for _, service := range c.DisplayServices() {
		for _, mode := range []ServiceRoutingMode{ServicesOnly, ServicesBypass} {
			s := ServiceSelection{Mode: mode, Only: []string{service.ID}, Bypass: []string{service.ID}}
			p, err = c.Resolve(s)
			if err != nil || p.Mode != mode || len(p.Networks)+len(p.Domains) == 0 {
				t.Fatal("owner service failed bounded resolution")
			}
		}
	}
	var all []string
	for _, service := range c.DisplayServices() {
		all = append(all, service.ID)
	}
	p, err = c.Resolve(ServiceSelection{Mode: ServicesOnly, Only: all})
	if err != nil || len(p.Networks) != 12478 || len(p.Domains) != 8 {
		t.Fatal("owner combined rules incomplete")
	}
}
