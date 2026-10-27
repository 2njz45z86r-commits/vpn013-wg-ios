// SPDX-License-Identifier: MIT
package r013routing

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// SnapshotSHA256 identifies the same reviewed RU policy in all three clients.
const SnapshotSHA256 = "0b947f48b2053a98616b33d9f5074aa0a8d15d092a7025d9080e3f2c29061679"
const NetworkCount = 10838

//go:embed networks.cidr
var snapshot string
var once sync.Once
var networks []netip.Prefix
var policyError error

func load() {
	if fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))) != SnapshotSHA256 {
		policyError = errors.New("embedded RU policy hash mismatch")
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(snapshot), "\n") {
		p, err := netip.ParsePrefix(line)
		if err != nil || p.Bits() == 0 || p != p.Masked() || !p.Addr().IsGlobalUnicast() {
			policyError = errors.New("invalid embedded RU policy")
			return
		}
		networks = append(networks, p)
	}
	if len(networks) != NetworkCount {
		policyError = errors.New("incomplete embedded RU policy")
	}
}

// Networks returns a defensive copy. No updater or caller can mutate policy.
func Networks() ([]netip.Prefix, error) {
	once.Do(load)
	return append([]netip.Prefix(nil), networks...), policyError
}

// Exclude subtracts registered RU ranges from one original OS route. It never
// expands the original route or rewrites a WireGuard peer's cryptographic route.
func Exclude(original netip.Prefix) ([]netip.Prefix, error) {
	if !original.IsValid() {
		return nil, errors.New("invalid original route")
	}
	ns, err := Networks()
	if err != nil {
		return nil, err
	}
	original = original.Masked()
	var walk func(netip.Prefix, int, int)
	out := make([]netip.Prefix, 0, 64)
	same := ns[:0:0]
	for _, n := range ns {
		if n.Addr().BitLen() == original.Addr().BitLen() && n.Overlaps(original) {
			same = append(same, n)
		}
	}
	walk = func(p netip.Prefix, lo, hi int) {
		if lo == hi {
			out = append(out, p)
			return
		}
		if same[lo].Bits() <= p.Bits() && same[lo].Contains(p.Addr()) {
			return
		}
		bits := p.Bits() + 1
		left := netip.PrefixFrom(p.Addr(), bits)
		raw := p.Addr().As16()
		offset := 128 - p.Addr().BitLen() + bits - 1
		raw[offset/8] |= 1 << uint(7-offset%8)
		a := netip.AddrFrom16(raw)
		if p.Addr().Is4() {
			a = a.Unmap()
		}
		right := netip.PrefixFrom(a, bits)
		mid := lo + sort.Search(hi-lo, func(i int) bool { return same[lo+i].Addr().Compare(right.Addr()) >= 0 })
		walk(left, lo, mid)
		walk(right, mid, hi)
	}
	walk(original, 0, len(same))
	if len(out) > 40000 {
		return nil, errors.New("RU route resource limit")
	}
	return out, nil
}

var active atomic.Bool

// Enable is called by the actual tunnel service before applying any network state.
func Enable()       { active.Store(true) }
func Enabled() bool { return active.Load() }
