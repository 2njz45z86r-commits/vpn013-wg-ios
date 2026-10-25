// SPDX-License-Identifier: MIT
package r013vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// WorkingDigest ignores only the reserved working label and observed byte/
// handshake counters. Every key, endpoint, DNS, route and AWG setting remains
// part of the match. It never returns serialized private configuration.
func WorkingDigest(configuration conf.Config) (string, error) {
	copy, err := CopyConfig(configuration)
	if err != nil {
		return "", ErrVault
	}
	copy.Name = r013.AutoName
	for i := range copy.Peers {
		copy.Peers[i].RxBytes = 0
		copy.Peers[i].TxBytes = 0
		copy.Peers[i].LastHandshakeTime = 0
	}
	wire, err := json.Marshal(copy)
	if err != nil {
		return "", ErrVault
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

// WorkingMember confirms exactly one immutable member. Neither identity-only
// aliases nor a missing/ambiguous snapshot can authorize seed/index0 fallback.
func (s Snapshot) WorkingMember(configuration conf.Config) (int, string, error) {
	if s.Count() < 1 || s.Count() > 30 || len(s.revision) != 64 {
		return -1, "", ErrVault
	}
	wanted, err := WorkingDigest(configuration)
	if err != nil {
		return -1, "", ErrVault
	}
	found := -1
	for i, member := range s.members {
		digest, err := WorkingDigest(member)
		if err != nil {
			return -1, "", ErrVault
		}
		if digest == wanted {
			if found != -1 {
				return -1, "", ErrVault
			}
			found = i
		}
	}
	if found < 0 {
		return -1, "", ErrVault
	}
	return found, s.digests[found], nil
}
