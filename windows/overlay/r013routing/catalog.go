// SPDX-License-Identifier: MIT
package r013routing

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"unicode"
)

const CatalogUIHash = "4fbaf9d8985c50b47465034165180393e11546c396027e5ded57e7c53f5475a3"
const CatalogRulesHash = "f69a0c79f3077981dca0600657b49a4a085610f76ef407a5f5e0d4874083476b"

type ServiceRoutingMode string

const (
	ServicesUnchanged ServiceRoutingMode = "unchanged"
	ServicesOnly      ServiceRoutingMode = "only_selected"
	ServicesBypass    ServiceRoutingMode = "bypass_selected"
)

// One mode represents both switches. The zero value preserves existing routes.
// Inactive choices are retained when switching modes, never silently selected.
type ServiceSelection struct {
	Mode   ServiceRoutingMode `json:"mode"`
	Only   []string           `json:"onlySelectedIds"`
	Bypass []string           `json:"bypassSelectedIds"`
}

func (s ServiceSelection) EffectiveMode() ServiceRoutingMode {
	if s.Mode == "" {
		return ServicesUnchanged
	}
	return s.Mode
}
func (s *ServiceSelection) SetOnly(enabled bool) {
	if enabled {
		s.Mode = ServicesOnly
	} else if s.EffectiveMode() == ServicesOnly {
		s.Mode = ServicesUnchanged
	}
}
func (s *ServiceSelection) SetBypass(enabled bool) {
	if enabled {
		s.Mode = ServicesBypass
	} else if s.EffectiveMode() == ServicesBypass {
		s.Mode = ServicesUnchanged
	}
}

// Display data deliberately has no network, domain, URL or executable fields.
type CatalogService struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Icon struct {
		Kind string `json:"kind"`
		Text string `json:"text"`
	} `json:"icon"`
	Category     string `json:"category"`
	ArchivedOnly bool   `json:"archivedOnly"`
}
type serviceRules struct {
	IPv4    []string `json:"ipv4"`
	Domains []string `json:"domains"`
}
type ServiceCatalog struct {
	services []CatalogService
	rules    map[string]serviceRules
}
type ServiceRoutePlan struct {
	Mode     ServiceRoutingMode
	Networks []netip.Prefix
	Domains  []string
}

func catalogJSON(data []byte, destination any) error {
	if len(data) == 0 || len(data) > 2*1024*1024 {
		return errors.New("catalog size rejected")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(destination); err != nil {
		return errors.New("catalog schema rejected")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing catalog data rejected")
	}
	return nil
}
func catalogID(s string) bool {
	if len(s) != 20 || !strings.HasPrefix(s, "svc_") {
		return false
	}
	for _, c := range s[4:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func catalogDomain(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// DecodeServiceCatalog accepts only the exact owner-reviewed, inert resources.
// It neither loads paths from the archive nor changes routes or tunnel state.
func DecodeServiceCatalog(ui, rules []byte) (*ServiceCatalog, error) {
	return decodeServiceCatalog(ui, rules, CatalogUIHash, CatalogRulesHash)
}
func decodeServiceCatalog(ui, rules []byte, uiHash, rulesHash string) (*ServiceCatalog, error) {
	if fmt.Sprintf("%x", sha256.Sum256(ui)) != uiHash || fmt.Sprintf("%x", sha256.Sum256(rules)) != rulesHash {
		return nil, errors.New("catalog hash mismatch")
	}
	var display struct {
		Version   int                  `json:"version"`
		Defaults  ServiceSelection     `json:"defaults"`
		Modes     []ServiceRoutingMode `json:"modes"`
		Exclusive bool                 `json:"mutuallyExclusiveSwitches"`
		Services  []CatalogService     `json:"services"`
	}
	var technical struct {
		Version  int                     `json:"version"`
		Services map[string]serviceRules `json:"services"`
	}
	if err := catalogJSON(ui, &display); err != nil {
		return nil, err
	}
	if err := catalogJSON(rules, &technical); err != nil {
		return nil, err
	}
	if display.Version != 1 || technical.Version != 1 || !display.Exclusive ||
		display.Defaults.Mode != ServicesUnchanged || len(display.Defaults.Only)+len(display.Defaults.Bypass) != 0 ||
		len(display.Modes) != 3 || display.Modes[0] != ServicesUnchanged || display.Modes[1] != ServicesOnly || display.Modes[2] != ServicesBypass ||
		len(display.Services) == 0 || len(display.Services) > 512 || len(technical.Services) != len(display.Services) {
		return nil, errors.New("catalog defaults or coverage rejected")
	}
	seen := make(map[string]bool)
	for _, service := range display.Services {
		if !catalogID(service.ID) || seen[service.ID] || service.Name == "" || len(service.Name) > 256 ||
			strings.Contains(service.Name, "://") || strings.IndexFunc(service.Name, unicode.IsControl) >= 0 ||
			service.Icon.Kind != "monogram" || len([]rune(service.Icon.Text)) < 1 || len([]rune(service.Icon.Text)) > 3 ||
			strings.IndexFunc(service.Icon.Text, unicode.IsControl) >= 0 || len(service.Category) > 256 {
			return nil, errors.New("catalog display rejected")
		}
		seen[service.ID] = true
		entry, ok := technical.Services[service.ID]
		if !ok || len(entry.IPv4)+len(entry.Domains) == 0 || len(entry.IPv4) > 16384 || len(entry.Domains) > 200 {
			return nil, errors.New("catalog rules rejected")
		}
		for _, raw := range entry.IPv4 {
			n, err := netip.ParsePrefix(raw)
			if err != nil || !n.Addr().Is4() || n != n.Masked() || n.Bits() == 0 ||
				!n.Addr().IsGlobalUnicast() || n.Addr().IsPrivate() || n.Addr().IsLoopback() || n.Addr().IsLinkLocalUnicast() {
				return nil, errors.New("catalog network rejected")
			}
		}
		for _, domain := range entry.Domains {
			if !catalogDomain(domain) {
				return nil, errors.New("catalog domain rejected")
			}
		}
	}
	return &ServiceCatalog{services: display.Services, rules: technical.Services}, nil
}

func (c *ServiceCatalog) DisplayServices() []CatalogService {
	return append([]CatalogService(nil), c.services...)
}

// SupportsWireGuard describes availability without exposing network rules.
func (c *ServiceCatalog) SupportsWireGuard(id string) bool {
	r, ok := c.rules[id]
	return ok && len(r.IPv4) > 0 && len(r.Domains) == 0
}

// A nil plan means leave the entire previous routing policy unchanged.
// Even an explicitly enabled mode cannot resolve with an empty selection.
func (c *ServiceCatalog) Resolve(s ServiceSelection) (*ServiceRoutePlan, error) {
	mode := s.EffectiveMode()
	if mode != ServicesUnchanged && mode != ServicesOnly && mode != ServicesBypass {
		return nil, errors.New("unknown service routing mode")
	}
	for _, ids := range [][]string{s.Only, s.Bypass} {
		if len(ids) > len(c.services) {
			return nil, errors.New("selection limit")
		}
		seen := make(map[string]bool)
		for _, id := range ids {
			if _, ok := c.rules[id]; !ok || seen[id] {
				return nil, errors.New("unknown or repeated service")
			}
			seen[id] = true
		}
	}
	if mode == ServicesUnchanged {
		return nil, nil
	}
	ids := s.Only
	if mode == ServicesBypass {
		ids = s.Bypass
	}
	if len(ids) == 0 {
		return nil, errors.New("select at least one service")
	}
	networks := make(map[netip.Prefix]bool)
	domains := make(map[string]bool)
	for _, id := range ids {
		entry := c.rules[id]
		for _, raw := range entry.IPv4 {
			networks[netip.MustParsePrefix(raw)] = true
		}
		for _, domain := range entry.Domains {
			domains[domain] = true
		}
	}
	if len(networks) > 16384 || len(domains) > 200 {
		return nil, errors.New("resolved service resource limit")
	}
	p := &ServiceRoutePlan{Mode: mode}
	for network := range networks {
		p.Networks = append(p.Networks, network)
	}
	for domain := range domains {
		p.Domains = append(p.Domains, domain)
	}
	sort.Slice(p.Networks, func(i, j int) bool {
		a, b := p.Networks[i], p.Networks[j]
		if a.Addr() != b.Addr() {
			return a.Addr().Less(b.Addr())
		}
		return a.Bits() < b.Bits()
	})
	sort.Strings(p.Domains)
	return p, nil
}
