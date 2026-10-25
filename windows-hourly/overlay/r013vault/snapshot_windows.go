// SPDX-License-Identifier: MIT
package r013vault

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const purpose = "VPN013-Auto-v1"
const maxVaultBytes = 2 * r013.MaxDocument

var ErrVault = errors.New("unchanged Auto vault snapshot is not confirmed")

// Snapshot retains existing DPAPI-protected Auto members in memory only. It
// never writes the vault or exposes private members through JSON serialization.
type Snapshot struct {
	members  []conf.Config
	digests  []string
	revision string
}

func (s Snapshot) Revision() string { return s.revision }
func (s Snapshot) Count() int       { return len(s.members) }
func (s Snapshot) Member(index int) (conf.Config, string, error) {
	if index < 0 || index >= len(s.members) {
		return conf.Config{}, "", ErrVault
	}
	wire, err := json.Marshal(s.members[index])
	if err != nil {
		return conf.Config{}, "", ErrVault
	}
	var copy conf.Config
	if json.Unmarshal(wire, &copy) != nil {
		return conf.Config{}, "", ErrVault
	}
	return copy, s.digests[index], nil
}
func EligibleForComparison(c conf.Config) bool {
	return strings.TrimSpace(c.Interface.PreUp+c.Interface.PostUp+c.Interface.PreDown+c.Interface.PostDown) == ""
}

// Decode uses the exact pre-existing description and user-scope DPAPI format.
// Production manager and tunnel service both run as SYSTEM; no new signer,
// purpose, keys, expiry or profile format is introduced. The ciphertext digest
// detects replacement even when names/count stay equal. Members are deep cloned.
func Decode(ciphertext []byte) (Snapshot, error) {
	var zero Snapshot
	if len(ciphertext) == 0 || len(ciphertext) > maxVaultBytes {
		return zero, ErrVault
	}
	raw, err := dpapi.Decrypt(ciphertext, purpose)
	if err != nil || len(raw) == 0 || len(raw) > maxVaultBytes {
		return zero, ErrVault
	}
	var members []conf.Config
	if json.Unmarshal(raw, &members) != nil || r013.ValidateCandidates(members) != nil {
		return zero, ErrVault
	}
	digests := make([]string, len(members))
	for i, member := range members {
		wire, err := json.Marshal(member)
		if err != nil {
			return zero, ErrVault
		}
		sum := sha256.Sum256(wire)
		digests[i] = hex.EncodeToString(sum[:])
	}
	revision := sha256.Sum256(ciphertext)
	return Snapshot{members: members, digests: digests, revision: hex.EncodeToString(revision[:])}, nil
}

// Load reads only the existing secure store. RootDirectory(false) deliberately
// does not create directories, repair ACLs or replace a missing vault with seed.
func Load() (Snapshot, error) {
	var zero Snapshot
	root, err := conf.RootDirectory(false)
	if err != nil {
		return zero, ErrVault
	}
	file := filepath.Join(root, "r013-auto.dat")
	link, err := os.Lstat(file)
	if err != nil || !link.Mode().IsRegular() || link.Mode()&os.ModeSymlink != 0 {
		return zero, ErrVault
	}
	handle, err := os.Open(file)
	if err != nil {
		return zero, ErrVault
	}
	defer handle.Close()
	before, err := handle.Stat()
	if err != nil || before.Size() == 0 || before.Size() > maxVaultBytes {
		return zero, ErrVault
	}
	data, err := io.ReadAll(io.LimitReader(handle, maxVaultBytes+1))
	if err != nil || len(data) > maxVaultBytes || int64(len(data)) != before.Size() {
		return zero, ErrVault
	}
	after, err := handle.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return zero, ErrVault
	}
	return Decode(data)
}
