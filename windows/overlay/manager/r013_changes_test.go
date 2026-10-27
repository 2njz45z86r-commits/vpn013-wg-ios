// SPDX-License-Identifier: MIT
package manager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
)

func TestOwnedRefreshPreservesKeysForeignProfilesAutoAndRollback(t *testing.T) {
	root := t.TempDir()
	conf.PresetRootDirectory(root)
	productionWriter := saveR013Config
	productionState := stateR013Tunnel
	defer func() { stateR013Tunnel = productionState }()
	stateR013Tunnel = func(*ManagerService, string) (TunnelState, error) { return TunnelStopped, nil }
	defer func() { saveR013Config = productionWriter }()
	// A desktop test token cannot assign SYSTEM file ownership. Preserve real
	// DPAPI encryption and filesystem recovery while leaving production ACL code
	// unchanged; no service or VPN is installed by this test.
	saveR013Config = func(c *conf.Config, overwrite bool) error {
		path, err := c.Path()
		if err != nil {
			return err
		}
		if !overwrite {
			if _, err = os.Stat(path); err == nil {
				return os.ErrExist
			}
		}
		raw, err := dpapi.Encrypt([]byte(c.ToWgQuick()), c.Name)
		if err != nil {
			return err
		}
		return writeProtected(path, raw)
	}
	makeConfig := func(name, endpoint string) *conf.Config {
		c, err := conf.FromWgQuick("[Interface]\nPrivateKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nJc = 3\n[Peer]\nPublicKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nPresharedKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = "+endpoint+":51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 15\n", name)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	original, foreign, added := makeConfig("OwnedTest", "192.0.2.1"), makeConfig("ForeignTest", "192.0.2.2"), makeConfig("AddedTest", "192.0.2.3")
	if err := saveR013Config(original, false); err != nil {
		t.Fatal(err)
	}
	if err := saveR013Config(foreign, false); err != nil {
		t.Fatal(err)
	}
	foreignBefore := foreign.ToWgQuick()
	service := &ManagerService{elevatedToken: 1}
	if err := service.CreateAuto([]conf.Config{*original, *foreign}); err != nil {
		t.Fatal(err)
	}
	next := makeConfig(original.Name, "192.0.2.4")
	changes := []r013.Change{{Name: original.Name, Expected: r013.Digest(original.ToWgQuick()), Config: next.ToWgQuick()}, {Name: added.Name, Config: added.ToWgQuick()}}
	if err := service.ApplyR013Changes(changes); err != nil {
		t.Fatal(err)
	}
	actual, err := conf.LoadFromName(original.Name)
	if err != nil {
		t.Fatal(err)
	}
	if actual.Interface.PrivateKey != original.Interface.PrivateKey || actual.Peers[0].PresharedKey != original.Peers[0].PresharedKey || actual.Peers[0].Endpoint.Host != "192.0.2.4" {
		t.Fatal("key identity or endpoint")
	}
	stateR013Tunnel = func(*ManagerService, string) (TunnelState, error) { return TunnelStarted, nil }
	if service.ApplyR013Changes([]r013.Change{{Name: original.Name, Expected: r013.Digest(next.ToWgQuick()), Remove: true}}) == nil {
		t.Fatal("active VPN guard")
	}
	stateR013Tunnel = func(*ManagerService, string) (TunnelState, error) { return TunnelStopped, nil }
	members, err := loadAuto()
	if err != nil || len(members) != 3 {
		t.Fatal("managed auto membership", err)
	}
	unchanged, _ := conf.LoadFromName(foreign.Name)
	if unchanged.ToWgQuick() != foreignBefore {
		t.Fatal("foreign profile modified")
	}
	if err = service.ApplyR013Changes([]r013.Change{{Name: original.Name, Expected: r013.Digest(original.ToWgQuick()), Remove: true}}); err == nil {
		t.Fatal("stale identity accepted")
	}
	actual, _ = conf.LoadFromName(original.Name)
	if actual.ToWgQuick() != next.ToWgQuick() {
		t.Fatal("stale guard changed profile")
	}
	// A locally deleted source remains owned by its exact previous Auto digest.
	if err = conf.DeleteName(original.Name); err != nil {
		t.Fatal(err)
	}
	restore := r013.Change{Name: original.Name, Expected: r013.Digest(next.ToWgQuick()), Config: next.ToWgQuick()}
	if service.ApplyR013Changes([]r013.Change{restore}) == nil {
		t.Fatal("missing source silently accepted without restoration intent")
	}
	restore.AllowMissing = true
	if err = service.ApplyR013Changes([]r013.Change{restore}); err != nil {
		t.Fatal("restore deleted source", err)
	}
	actual, err = conf.LoadFromName(original.Name)
	if err != nil || actual.ToWgQuick() != next.ToWgQuick() {
		t.Fatal("restored source changed keys", err)
	}
	if err = conf.DeleteName(original.Name); err != nil {
		t.Fatal(err)
	}
	bad := restore
	bad.Expected = r013.Digest("foreign")
	if service.ApplyR013Changes([]r013.Change{bad}) == nil {
		t.Fatal("Auto ownership proof bypassed")
	}
	bad.Expected = ""
	if service.ApplyR013Changes([]r013.Change{bad}) == nil {
		t.Fatal("empty restoration proof accepted")
	}
	if err = conf.DeleteName(added.Name); err != nil {
		t.Fatal(err)
	}
	if err = service.ApplyR013Changes([]r013.Change{restore, {Name: added.Name, Expected: r013.Digest(added.ToWgQuick()), Config: added.ToWgQuick(), AllowMissing: true}}); err != nil {
		t.Fatal("restore all managed sources", err)
	}
	members, err = loadAuto()
	if err != nil || len(members) != 3 {
		t.Fatal("Auto restoration", err)
	}
	// A retired source already deleted locally must be removable idempotently.
	if err = conf.DeleteName(added.Name); err != nil {
		t.Fatal(err)
	}
	if err = service.ApplyR013Changes([]r013.Change{{Name: original.Name, Expected: r013.Digest(next.ToWgQuick()), Remove: true}, {Name: added.Name, Expected: r013.Digest(added.ToWgQuick()), Remove: true, AllowMissing: true}}); err != nil {
		t.Fatal(err)
	}
	members, err = loadAuto()
	if err != nil || len(members) != 1 || members[0].Name != foreign.Name {
		t.Fatal("foreign Auto member lost")
	}
	path, _ := foreign.Path()
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = saveR013Config(makeConfig(foreign.Name, "192.0.2.5"), true); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal([]rollbackFile{{path, before, true}})
	protected, _ := dpapi.Encrypt(raw, "VPN013-transaction-v1")
	journal, _ := rollbackPath()
	os.WriteFile(journal, protected, 0600)
	if err = recoverR013Transaction(); err != nil {
		t.Fatal(err)
	}
	restored, _ := conf.LoadFromName(foreign.Name)
	if restored.ToWgQuick() != foreignBefore {
		t.Fatal("recovery did not restore original")
	}
	raw, _ = json.Marshal([]rollbackFile{{filepath.Join(root, "..", "outside-test.txt"), []byte("must not write"), true}})
	protected, _ = dpapi.Encrypt(raw, "VPN013-transaction-v1")
	os.WriteFile(journal, protected, 0600)
	if recoverR013Transaction() == nil {
		t.Fatal("outside recovery path accepted")
	}
	os.Remove(journal)
	if _, err = os.Stat(filepath.Join(root, "..", "outside-test.txt")); !os.IsNotExist(err) {
		t.Fatal("outside sentinel written")
	}
}
