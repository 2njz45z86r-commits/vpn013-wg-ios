// SPDX-License-Identifier: MIT
package r013

import (
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"sort"
	"strings"
	"testing"
)

func TestAutoFirstAndNaturalOrdinaryOrdering(t *testing.T) {
	names := []string{"Дом", "+Первый", "Finland10", "Finland2", "0Server", AutoName, "Germany"}
	sort.SliceStable(names, func(i, j int) bool { return ProfileNameLess(names[i], names[j]) })
	if names[0] != AutoName {
		t.Fatal("Auto sorted after ordinary profile")
	}
	for i := 2; i < len(names); i++ {
		if conf.TunnelNameIsLess(names[i], names[i-1]) {
			t.Fatal("Ordinary order changed")
		}
	}
	for _, a := range names {
		if ProfileNameLess(a, a) {
			t.Fatal("Comparator is not strict")
		}
		for _, b := range names {
			if ProfileNameLess(a, b) && ProfileNameLess(b, a) {
				t.Fatal("Comparator is not asymmetric")
			}
		}
	}
}

func TestCurrentPingRuntimeMembershipAndManualFallback(t *testing.T) {
	parse := func(host string) *conf.Config {
		c, err := conf.FromWgQuick("[Interface]\nPrivateKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.13.0.2/32\n[Peer]\nPublicKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = "+host+"\nAllowedIPs = 0.0.0.0/0\n", "Sample")
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	seed, active := parse("192.0.2.10:51820"), parse("[2001:db8::2]:51821")
	if _, err := CurrentTarget(AutoName, nil, seed); err == nil {
		t.Fatal("Auto accepted stored seed")
	}
	got, err := CurrentTarget(AutoName, active, seed)
	if err != nil || got.Host != "2001:db8::2" || got.StoredFallback {
		t.Fatal("Auto did not use live peer")
	}
	manual, err := CurrentTarget("Manual", nil, seed)
	if err != nil || manual.Host != "192.0.2.10" || !manual.StoredFallback {
		t.Fatal("Manual statistics failure disabled known endpoint")
	}
	fresh, err := CurrentTarget("Manual", active, seed)
	if err != nil || fresh.Identity == manual.Identity || fresh.StoredFallback {
		t.Fatal("Changed peer retained old identity")
	}
	if strings.Contains(fresh.Identity, active.Interface.PrivateKey.String()) || len(fresh.Identity) != 64 {
		t.Fatal("Identity is not a public digest")
	}
	if _, err := CurrentTarget("Manual", &conf.Config{}, &conf.Config{}); err == nil {
		t.Fatal("Empty profile acquired ping target")
	}
	copy := *seed
	copy.Peers = append(copy.Peers, copy.Peers[0])
	if _, err := CurrentTarget(AutoName, &copy, seed); err == nil {
		t.Fatal("Ambiguous Auto accepted")
	}
}
