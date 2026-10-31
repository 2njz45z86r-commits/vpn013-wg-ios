// SPDX-License-Identifier: MIT
package r013routing

import (
	"bytes"
	"encoding/json"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestServiceMetadataDPAPIAtomicBinding(t *testing.T) {
	root := t.TempDir()
	conf.PresetRootDirectory(root)
	cat, err := OwnerCatalog()
	if err != nil {
		t.Fatal(err)
	}
	id := ""
	for _, s := range cat.DisplayServices() {
		p, e := cat.Resolve(ServiceSelection{Mode: ServicesOnly, Only: []string{s.ID}})
		if e == nil && len(p.Domains) == 0 {
			id = s.ID
			break
		}
	}
	if id == "" {
		t.Fatal("missing static service")
	}
	c := &conf.Config{Name: "Fixture"}
	doc := ServicePolicies{Version: 1, Profiles: []ProfilePolicy{{Name: c.Name, SourceDigest: ProfileSourceDigest(c), Selection: ServiceSelection{Mode: ServicesOnly, Only: []string{id}}}}}
	if err = SaveServicePolicies(doc); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, serviceMetadataFile))
	if err != nil || bytes.Contains(raw, []byte(id)) || bytes.Contains(raw, []byte("Fixture")) {
		t.Fatal("metadata is not protected")
	}
	read, err := LoadServicePolicies()
	if err != nil {
		t.Fatal(err)
	}
	s, err := read.ForProfile(c)
	if err != nil || s.Mode != ServicesOnly || len(s.Only) != 1 || s.Only[0] != id {
		t.Fatal("binding did not round trip")
	}
	c.Interface.ListenPort = 1234
	if _, err = read.ForProfile(c); err == nil {
		t.Fatal("stale source accepted")
	}
}
func TestServiceMetadataRejectsInvalidWithoutReplacing(t *testing.T) {
	root := t.TempDir()
	conf.PresetRootDirectory(root)
	if err := SaveServicePolicies(ServicePolicies{Version: 1}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, serviceMetadataFile))
	if err != nil {
		t.Fatal(err)
	}
	err = SaveServicePolicies(ServicePolicies{Version: 1, Profiles: []ProfilePolicy{{Name: "Fixture", SourceDigest: "invalid", Selection: ServiceSelection{Mode: ServicesOnly, Only: []string{"unknown"}}}}})
	if err == nil {
		t.Fatal("invalid metadata accepted")
	}
	after, err := os.ReadFile(filepath.Join(root, serviceMetadataFile))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("invalid update changed metadata")
	}
}

func TestServiceAutoPolicyVaultAndCandidateFence(t *testing.T) {
	root := t.TempDir()
	conf.PresetRootDirectory(root)
	defer activeService.Store(nil)
	makeConfig := func(name, endpoint, dns string) conf.Config {
		c, e := conf.FromWgQuick("[Interface]\nPrivateKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.13.0.2/32\nDNS = "+dns+"\n[Peer]\nPublicKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = "+endpoint+":51820\nAllowedIPs = 0.0.0.0/0\n", name)
		if e != nil {
			t.Fatal(e)
		}
		return *c
	}
	one, two := makeConfig("One", "192.0.2.1", "9.9.9.9"), makeConfig("Two", "192.0.2.2", "9.9.9.9")
	writeVault := func(members []conf.Config) {
		raw, e := json.Marshal(members)
		if e != nil {
			t.Fatal(e)
		}
		raw, e = dpapi.Encrypt(raw, "VPN013-Auto-v1")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, "r013-auto.dat"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeVault([]conf.Config{one, two})
	current := one
	current.Name = r013.AutoName
	cat, e := OwnerCatalog()
	if e != nil {
		t.Fatal(e)
	}
	selection := ServiceSelection{Mode: ServicesOnly}
	for _, s := range cat.DisplayServices() {
		selection.Only = []string{s.ID}
		if e = ValidateProfileForServicePolicy(&current, selection); e == nil {
			break
		}
	}
	revision, e := ValidateAutoServiceMembers(&current, selection)
	if e != nil {
		t.Fatal(e)
	}
	if e = SaveServicePolicies(ServicePolicies{Version: 1, Profiles: []ProfilePolicy{{Name: r013.AutoName, SourceDigest: revision, Selection: selection}}}); e != nil {
		t.Fatal(e)
	}
	if e = ActivateProfileServicePolicy(&current); e != nil {
		t.Fatal(e)
	}
	if e = ValidateActiveAutoMember(&two); e != nil {
		t.Fatal("compatible member rejected", e)
	}
	incompatible := two
	incompatible.Interface.DNS = []net.IP{net.ParseIP("4.4.4.4")}
	if ValidateActiveAutoMember(&incompatible) == nil {
		t.Fatal("different policy accepted")
	}
	writeVault([]conf.Config{one, two})
	if ValidateActiveAutoMember(&two) == nil {
		t.Fatal("replaced vault accepted")
	}
	if e = ValidateActiveAutoRestore(&current); e != nil {
		t.Fatal("safe rollback blocked", e)
	}
	if e = ActivateProfileServicePolicy(&current); e == nil {
		t.Fatal("stale saved vault binding accepted")
	}
}
