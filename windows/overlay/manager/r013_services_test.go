// SPDX-License-Identifier: MIT
package manager

import (
	"bytes"
	"encoding/gob"
	"errors"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"reflect"
	"testing"
)

func TestServicePoliciesAtomicTargetsAndActiveFence(t *testing.T) {
	oldLoad, oldSave, oldConfig, oldState := loadServicePolicies, saveServicePolicies, loadServiceConfig, stateR013Tunnel
	defer func() {
		loadServicePolicies, saveServicePolicies, loadServiceConfig, stateR013Tunnel = oldLoad, oldSave, oldConfig, oldState
	}()
	cfg := func(name string) *conf.Config {
		c, e := conf.FromWgQuick("[Interface]\nPrivateKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.13.0.2/32\nDNS = 9.9.9.9\n[Peer]\nPublicKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n", name)
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	one, two, foreign := cfg("One"), cfg("Two"), cfg("Foreign")
	configs := map[string]*conf.Config{"One": one, "Two": two, "Foreign": foreign}
	cat, e := r013routing.OwnerCatalog()
	if e != nil {
		t.Fatal(e)
	}
	id := ""
	for _, s := range cat.DisplayServices() {
		selection := r013routing.ServiceSelection{Mode: r013routing.ServicesOnly, Only: []string{s.ID}}
		if e = r013routing.ValidateProfileForServicePolicy(one, selection); e == nil {
			id = s.ID
			break
		}
	}
	if id == "" {
		t.Fatal("no eligible fixture service")
	}
	old := r013routing.ServicePolicies{Version: 1, Profiles: []r013routing.ProfilePolicy{{Name: "Foreign", SourceDigest: r013routing.ProfileSourceDigest(foreign)}}}
	loadServicePolicies = func() (r013routing.ServicePolicies, error) { return old, nil }
	writes := 0
	var saved r013routing.ServicePolicies
	saveServicePolicies = func(v r013routing.ServicePolicies) error { writes++; saved = v; return nil }
	loadServiceConfig = func(name string) (*conf.Config, error) {
		v := configs[name]
		if v == nil {
			return nil, errors.New("missing")
		}
		return v, nil
	}
	stateR013Tunnel = func(_ *ManagerService, name string) (TunnelState, error) {
		if name == "Two" {
			return TunnelStarted, nil
		}
		return TunnelStopped, nil
	}
	sel := r013routing.ServiceSelection{Mode: r013routing.ServicesOnly, Only: []string{id}}
	changes := []r013routing.ProfilePolicy{{Name: "One", SourceDigest: r013routing.ProfileSourceDigest(one), Selection: sel}, {Name: "Two", SourceDigest: r013routing.ProfileSourceDigest(two), Selection: sel}}
	service := &ManagerService{elevatedToken: 1}
	if service.UpdateServicePolicies(changes) == nil || writes != 0 {
		t.Fatal("active target caused partial write")
	}
	stateR013Tunnel = func(*ManagerService, string) (TunnelState, error) { return TunnelStopped, nil }
	changes[1].SourceDigest = "stale"
	if service.UpdateServicePolicies(changes) == nil || writes != 0 {
		t.Fatal("stale target caused partial write")
	}
	changes[1].SourceDigest = r013routing.ProfileSourceDigest(two)
	if e = service.UpdateServicePolicies(changes); e != nil || writes != 1 || len(saved.Profiles) != 3 || !reflect.DeepEqual(saved.Profiles[0], old.Profiles[0]) {
		t.Fatal("target scope or atomic write", e)
	}
	if service.UpdateServicePolicies([]r013routing.ProfilePolicy{{Name: r013.AutoName}}) == nil || writes != 1 {
		t.Fatal("unverified Auto accepted")
	}
	if (&ManagerService{}).UpdateServicePolicies(changes) == nil || writes != 1 {
		t.Fatal("unauthorized caller accepted")
	}
}

func TestServicePoliciesLogicalAutoKeepsManualChoices(t *testing.T) {
	oldLoad, oldSave, oldConfig, oldState, oldDigest, oldAuto := loadServicePolicies, saveServicePolicies, loadServiceConfig, stateR013Tunnel, serviceTargetDigest, validateAutoServices
	defer func() {
		loadServicePolicies, saveServicePolicies, loadServiceConfig, stateR013Tunnel, serviceTargetDigest, validateAutoServices = oldLoad, oldSave, oldConfig, oldState, oldDigest, oldAuto
	}()
	manual := r013routing.ProfilePolicy{Name: "Manual", SourceDigest: "old", Selection: r013routing.ServiceSelection{Mode: r013routing.ServicesUnchanged}}
	loadServicePolicies = func() (r013routing.ServicePolicies, error) {
		return r013routing.ServicePolicies{Version: 1, Profiles: []r013routing.ProfilePolicy{manual}}, nil
	}
	var saved r013routing.ServicePolicies
	saveServicePolicies = func(p r013routing.ServicePolicies) error { saved = p; return nil }
	loadServiceConfig = func(name string) (*conf.Config, error) { return &conf.Config{Name: name}, nil }
	stateR013Tunnel = func(*ManagerService, string) (TunnelState, error) { return TunnelStopped, nil }
	serviceTargetDigest = func(*conf.Config) (string, error) { return "vault-revision", nil }
	calls := 0
	validateAutoServices = func(_ *conf.Config, s r013routing.ServiceSelection) (string, error) {
		calls++
		if s.EffectiveMode() != r013routing.ServicesOnly {
			return "", errors.New("wrong mode")
		}
		return "vault-revision", nil
	}
	change := r013routing.ProfilePolicy{Name: r013.AutoName, SourceDigest: "vault-revision", Selection: r013routing.ServiceSelection{Mode: r013routing.ServicesOnly, Only: []string{"fixture"}}}
	if err := (&ManagerService{elevatedToken: 1}).UpdateServicePolicies([]r013routing.ProfilePolicy{change}); err != nil || calls != 1 || len(saved.Profiles) != 2 || !reflect.DeepEqual(saved.Profiles[0], manual) {
		t.Fatal("Auto policy changed manual binding", err)
	}
}

func TestServicePoliciesTypedManagerIPC(t *testing.T) {
	old := loadServicePolicies
	defer func() { loadServicePolicies = old }()
	loadServicePolicies = func() (r013routing.ServicePolicies, error) { return r013routing.ServicePolicies{Version: 1}, nil }
	var requests, responses bytes.Buffer
	enc := gob.NewEncoder(&requests)
	if err := enc.Encode(GetServicePoliciesMethodType); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode(UpdateServicePoliciesMethodType); err != nil {
		t.Fatal(err)
	}
	if err := enc.Encode([]r013routing.ProfilePolicy{}); err != nil {
		t.Fatal(err)
	}
	(&ManagerService{elevatedToken: 1}).ServeConn(&requests, &responses)
	dec := gob.NewDecoder(&responses)
	var state r013routing.ServicePolicies
	var first, second string
	if err := dec.Decode(&state); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&second); err != nil {
		t.Fatal(err)
	}
	if state.Version != 1 || first != "" || second == "" {
		t.Fatal("typed RPC response or empty target guard failed")
	}
}
