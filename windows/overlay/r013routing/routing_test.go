// SPDX-License-Identifier: MIT
package r013routing

import (
	"math/rand"
	"net/netip"
	"sort"
	"testing"
)

func has(rows []netip.Prefix, a netip.Addr) bool {
	i := sort.Search(len(rows), func(i int) bool { return rows[i].Addr().Compare(a) > 0 })
	return i > 0 && rows[i-1].Contains(a)
}
func TestRussianSplitCoversExactlyComplement(t *testing.T) {
	ns, err := Networks()
	if err != nil {
		t.Fatal(err)
	}
	rnd := rand.New(rand.NewSource(13026))
	for _, root := range []string{"0.0.0.0/0", "::/0", "2.56.24.0/24", "8.8.8.0/24", "2001:640::/40", "2001:4860::/32", "10.0.0.0/8"} {
		p := netip.MustParsePrefix(root)
		routes, err := Exclude(p)
		if err != nil {
			t.Fatal(err)
		}
		var same []netip.Prefix
		for _, n := range ns {
			if n.Addr().BitLen() == p.Addr().BitLen() {
				same = append(same, n)
			}
		}
		for _, r := range routes {
			if !p.Contains(r.Addr()) || r.Bits() < p.Bits() {
				t.Fatal("route expands profile")
			}
			i := sort.Search(len(same), func(i int) bool { return same[i].Addr().Compare(r.Addr()) >= 0 })
			if (i < len(same) && r.Overlaps(same[i])) || (i > 0 && r.Overlaps(same[i-1])) {
				t.Fatalf("RU overlap %v", r)
			}
		}
		for i := 0; i < 2000; i++ {
			var b [16]byte
			rnd.Read(b[:])
			a := netip.AddrFrom16(b)
			if p.Addr().Is4() {
				var v [4]byte
				copy(v[:], b[:4])
				a = netip.AddrFrom4(v)
			}
			if has(routes, a) != (p.Contains(a) && !has(same, a)) {
				t.Fatalf("split differs at %v", a)
			}
		}
		t.Logf("%s -> %d owned TUN prefixes", root, len(routes))
	}
	ns[0] = netip.MustParsePrefix("0.0.0.0/0")
	again, err := Networks()
	if err != nil || again[0].Bits() == 0 {
		t.Fatal("policy mutable")
	}
}
func TestEmbeddedPolicyFailureRefusesInvalidRoute(t *testing.T) {
	if _, err := Exclude(netip.Prefix{}); err == nil {
		t.Fatal("invalid route accepted")
	}
}
