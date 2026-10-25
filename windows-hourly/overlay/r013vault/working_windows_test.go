// SPDX-License-Identifier: MIT
package r013vault

import (
	"encoding/json"
	"net"
	"testing"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
)

func TestWorkingMemberRequiresExactSettingsAndUniqueSnapshot(t *testing.T) {
	fixtureCI(t)
	original := member(t, "original")
	alias, _ := CopyConfig(original)
	alias.Name = "alias"
	alias.Interface.MTU = 1300
	wire, _ := json.Marshal([]conf.Config{original, alias})
	cipher, err := dpapi.Encrypt(wire, purpose)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Decode(cipher)
	if err != nil {
		t.Fatal(err)
	}
	working, _ := CopyConfig(alias)
	working.Name = "R013-Auto"
	working.Peers[0].RxBytes = 100
	working.Peers[0].LastHandshakeTime = 1000
	index, digest, err := snapshot.WorkingMember(working)
	if err != nil || index != 1 || len(digest) != 64 {
		t.Fatal("full settings did not select exact second alias")
	}
	changes := map[string]func(*conf.Config){
		"dns":         func(c *conf.Config) { c.Interface.DNS = []net.IP{{1, 1, 1, 1}} },
		"route":       func(c *conf.Config) { c.Peers[0].AllowedIPs[0].Cidr = 1 },
		"endpoint":    func(c *conf.Config) { c.Peers[0].Endpoint.Host = "changed.invalid" },
		"port":        func(c *conf.Config) { c.Peers[0].Endpoint.Port++ },
		"mtu":         func(c *conf.Config) { c.Interface.MTU++ },
		"key":         func(c *conf.Config) { c.Interface.PrivateKey[0] ^= 1 },
		"obfuscation": func(c *conf.Config) { c.Interface.JunkPacketCount++ },
		"ipacket":     func(c *conf.Config) { c.Interface.IPackets["I1"] = "changed" },
		"search":      func(c *conf.Config) { c.Interface.DNSSearch = []string{"changed.invalid"} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			copy, _ := CopyConfig(working)
			change(&copy)
			if index, _, err := snapshot.WorkingMember(copy); err == nil || index != -1 {
				t.Fatal("changed settings became confirmed member")
			}
		})
	}
	duplicate, _ := CopyConfig(original)
	duplicate.Name = "another label"
	wire, _ = json.Marshal([]conf.Config{original, duplicate})
	cipher, _ = dpapi.Encrypt(wire, purpose)
	snapshot, err = Decode(cipher)
	if err != nil {
		t.Fatal(err)
	}
	if index, _, err := snapshot.WorkingMember(original); err == nil || index != -1 {
		t.Fatal("ambiguous same settings guessed an index")
	}
	if index, _, err := (Snapshot{}).WorkingMember(original); err == nil || index != -1 {
		t.Fatal("missing vault guessed index zero")
	}
}
