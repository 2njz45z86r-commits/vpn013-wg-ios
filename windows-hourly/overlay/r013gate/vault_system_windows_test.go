// SPDX-License-Identifier: MIT
package r013gate

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"net"
)

// Called only by the guarded disposable SCM SYSTEM fixture after actual drop.
// It does not read/write the real store or any owner's profile/signing key.
func proveSystemVaultRead() error {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	remote, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	config := conf.Config{Name: "SYSTEM-vault-fixture", Interface: conf.Interface{Addresses: []conf.IPCidr{{IP: net.ParseIP("10.213.77.2").To4(), Cidr: 32}}}, Peers: []conf.Peer{{Endpoint: conf.Endpoint{Host: "fixture.invalid", Port: 51820}, AllowedIPs: []conf.IPCidr{{IP: net.IPv4zero.To4(), Cidr: 0}}}}}
	copy(config.Interface.PrivateKey[:], private.Bytes())
	copy(config.Peers[0].PublicKey[:], remote.PublicKey().Bytes())
	wire, err := json.Marshal([]conf.Config{config})
	if err != nil {
		return err
	}
	cipher, err := dpapi.Encrypt(wire, "VPN013-Auto-v1")
	if err != nil {
		return errors.New("SYSTEM legacy DPAPI encryption failed")
	}
	original := append([]byte(nil), cipher...)
	snapshot, err := r013vault.Decode(cipher)
	if err != nil {
		return errors.New("SYSTEM legacy DPAPI snapshot decoding failed")
	}
	member, digest, err := snapshot.Member(0)
	if err != nil || snapshot.Count() != 1 || len(snapshot.Revision()) != 64 || len(digest) != 64 || member.Interface.PrivateKey != config.Interface.PrivateKey || member.Peers[0].PublicKey != config.Peers[0].PublicKey || string(original) != string(cipher) {
		return errors.New("SYSTEM vault identity/settings changed")
	}
	return nil
}
