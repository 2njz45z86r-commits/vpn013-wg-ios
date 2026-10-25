// SPDX-License-Identifier: MIT
package r013vault

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"net"
	"os"
	"testing"
)

func fixtureCI(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" {
		t.Fatal("disposable native CI required; never read owner vault")
	}
}
func member(t *testing.T, name string) conf.Config {
	t.Helper()
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := conf.Config{Name: name, Interface: conf.Interface{Addresses: []conf.IPCidr{{IP: net.ParseIP("10.213.77.2").To4(), Cidr: 32}}, DNS: []net.IP{net.ParseIP("10.213.77.1").To4()}, IPackets: map[string]string{"I1": "fixture-preserved"}}, Peers: []conf.Peer{{AllowedIPs: []conf.IPCidr{{IP: net.IPv4zero.To4(), Cidr: 0}}, Endpoint: conf.Endpoint{Host: "fixture.invalid", Port: 51820}}}}
	copy(c.Interface.PrivateKey[:], private.Bytes())
	copy(c.Peers[0].PublicKey[:], server.PublicKey().Bytes())
	return c
}
func TestLegacyDPAPIVaultSnapshotPreservesKeysSettingsAndDeepClone(t *testing.T) {
	fixtureCI(t)
	original := []conf.Config{member(t, "one"), member(t, "two")}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := dpapi.Encrypt(raw, purpose)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), encrypted...)
	snapshot, err := Decode(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Count() != 2 || len(snapshot.Revision()) != 64 {
		t.Fatal("legacy member count/revision missing")
	}
	first, digest, err := snapshot.Member(0)
	if err != nil || len(digest) != 64 || first.Interface.PrivateKey != original[0].Interface.PrivateKey || first.Peers[0].PublicKey != original[0].Peers[0].PublicKey || first.Interface.IPackets["I1"] != "fixture-preserved" {
		t.Fatal("legacy key/settings changed")
	}
	if first.Interface.Addresses[0].Bits() != 32 || first.Peers[0].AllowedIPs[0].Bits() != 32 || len(first.Interface.DNS[0]) != 4 {
		t.Fatal("JSON IPv4 representation changed native family/route semantics")
	}
	beforeClone, _ := json.Marshal(first)
	first.Interface.PrivateKey[0] ^= 1
	first.Interface.Addresses[0].IP[0] ^= 1
	first.Interface.IPackets["I1"] = "changed"
	first.Peers[0].AllowedIPs[0].IP[0] ^= 1
	second, again, _ := snapshot.Member(0)
	afterClone, _ := json.Marshal(second)
	// net.IP's JSON decoder normalizes IPv4 to a 16-byte representation;
	// compare the address and complete canonical wire, not slice byte zero.
	if second.Interface.PrivateKey != original[0].Interface.PrivateKey || second.Interface.IPackets["I1"] != "fixture-preserved" || again != digest || !second.Interface.Addresses[0].IP.Equal(original[0].Interface.Addresses[0].IP) || !second.Peers[0].AllowedIPs[0].IP.Equal(original[0].Peers[0].AllowedIPs[0].IP) || string(beforeClone) != string(afterClone) {
		t.Fatal("caller mutated immutable vault snapshot")
	}
	if string(encrypted) != string(before) {
		t.Fatal("decoder changed encrypted vault")
	}
	exposed, _ := json.Marshal(snapshot)
	if string(exposed) != "{}" {
		t.Fatal("private vault members were JSON-visible")
	}
	second.Interface.PreUp = "test-only-no-execution"
	if EligibleForComparison(second) {
		t.Fatal("scripted profile was eligible for background comparison")
	}
}
func TestVaultRefusesWrongPurposeCorruptionAndBoundsWithoutSeedFallback(t *testing.T) {
	fixtureCI(t)
	raw, _ := json.Marshal([]conf.Config{member(t, "one")})
	wrong, err := dpapi.Encrypt(raw, "different-purpose")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, []byte("corrupt"), wrong, make([]byte, maxVaultBytes+1)} {
		if _, err := Decode(bad); err == nil {
			t.Fatal("unconfirmed vault substituted a usable snapshot")
		}
	}
	one, _ := dpapi.Encrypt(raw, purpose)
	changed := member(t, "one")
	changed.Interface.MTU = 1300
	wire, _ := json.Marshal([]conf.Config{changed})
	two, _ := dpapi.Encrypt(wire, purpose)
	a, err := Decode(one)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Decode(two)
	if err != nil {
		t.Fatal(err)
	}
	_, idA, _ := a.Member(0)
	_, idB, _ := b.Member(0)
	if a.Revision() == b.Revision() || idA == idB {
		t.Fatal("changed member/vault was not distinguished")
	}
	if _, _, err = a.Member(-1); err == nil {
		t.Fatal("invalid member index accepted")
	}
}
