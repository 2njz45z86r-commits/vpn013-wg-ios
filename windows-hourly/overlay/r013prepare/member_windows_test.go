// SPDX-License-Identifier: MIT
package r013prepare

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

type resolverFixture struct {
	calls   atomic.Uint32
	answers []netip.Addr
	err     error
	started chan struct{}
	block   bool
}

func (r *resolverFixture) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.calls.Add(1)
	if r.started != nil {
		close(r.started)
	}
	if r.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return r.answers, r.err
}
func fixtureMember(t *testing.T) conf.Config {
	t.Helper()
	private, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	remote, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c := conf.Config{Name: "synthetic-only", Interface: conf.Interface{Addresses: []conf.IPCidr{{IP: net.ParseIP("10.213.77.2").To4(), Cidr: 32}}, DNS: []net.IP{net.ParseIP("10.213.77.1").To4()}, MTU: 1370, IPackets: map[string]string{"i1": "fixture-preserved"}}, Peers: []conf.Peer{{Endpoint: conf.Endpoint{Host: "fixture.invalid", Port: 51820}, AllowedIPs: []conf.IPCidr{{IP: net.IPv4zero.To4(), Cidr: 0}}}}}
	copy(c.Interface.PrivateKey[:], private.Bytes())
	copy(c.Peers[0].PublicKey[:], remote.PublicKey().Bytes())
	return c
}
func otherIdentity(t *testing.T) string {
	t.Helper()
	s, e := Identity(fixtureMember(t))
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestActiveClientServerAliasRefusedBeforeAnyEndpointResolution(t *testing.T) {
	for _, variant := range []string{"original", "renamed-domain", "clamped-private-alias"} {
		t.Run(variant, func(t *testing.T) {
			c := fixtureMember(t)
			active, e := Identity(c)
			if e != nil {
				t.Fatal(e)
			}
			if variant == "renamed-domain" {
				c.Name = "another-name"
				c.Peers[0].Endpoint.Host = "another.invalid"
			}
			if variant == "clamped-private-alias" {
				c.Interface.PrivateKey[0] ^= 7
				c.Interface.PrivateKey[31] ^= 128
			}
			r := &resolverFixture{answers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
			if _, e = Prepare(context.Background(), c, active, Roles{Physical4: 7}, r); !errors.Is(e, probe.ErrActiveIdentity) || r.calls.Load() != 0 {
				t.Fatal("active alias performed resolution")
			}
		})
	}
}

func TestPreparedNumericEndpointKeepsExactOriginalKeysSettingsAndDomain(t *testing.T) {
	c := fixtureMember(t)
	before, _ := json.Marshal(c)
	r := &resolverFixture{answers: []netip.Addr{netip.MustParseAddr("192.0.2.123")}}
	m, e := Prepare(context.Background(), c, otherIdentity(t), Roles{Physical4: 7}, r)
	if e != nil {
		t.Fatal(e)
	}
	if r.calls.Load() != 1 || m.Endpoint().String() != "192.0.2.123:51820" || m.Source().String() != "10.213.77.2" || !strings.Contains(m.UAPI(), "endpoint=192.0.2.123:51820\n") {
		t.Fatal("prepared endpoint is not exact numeric source")
	}
	original, e := m.Original()
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(original)
	if string(wire) != string(before) || original.Interface.Addresses[0].Bits() != 32 || original.Peers[0].AllowedIPs[0].Bits() != 32 {
		t.Fatal("keys/domain/settings or native family changed")
	}
	original.Interface.IPackets["i1"] = "changed"
	c.Interface.PrivateKey[0] ^= 1
	c.Interface.IPackets["i1"] = "caller-changed"
	original, e = m.Original()
	if e != nil {
		t.Fatal(e)
	}
	wire, _ = json.Marshal(original)
	if string(wire) != string(before) {
		t.Fatal("prepared snapshot shared caller maps/keys")
	}
	// Numeric input performs no resolver call; ToUAPI sees a numeric address.
	numeric := fixtureMember(t)
	numeric.Peers[0].Endpoint.Host = "192.0.2.111"
	unused := &resolverFixture{err: errors.New("must not resolve")}
	if _, e = Prepare(context.Background(), numeric, otherIdentity(t), Roles{Physical4: 7}, unused); e != nil || unused.calls.Load() != 0 {
		t.Fatal("numeric preparation performed DNS")
	}
}

func TestEndpointPreparationRefusesUnknownRouteIdentityAndResolverFailures(t *testing.T) {
	for _, scenario := range []string{"unknown-role", "unknown-identity", "resolver-error", "unroutable-v6", "multicast-only", "overlong-host"} {
		t.Run(scenario, func(t *testing.T) {
			c := fixtureMember(t)
			roles := Roles{Physical4: 7}
			active := otherIdentity(t)
			r := &resolverFixture{answers: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
			switch scenario {
			case "unknown-role":
				roles = Roles{}
			case "unknown-identity":
				active = strings.Repeat("?", 64)
			case "resolver-error":
				r.err = errors.New("synthetic lookup failed")
			case "unroutable-v6":
				r.answers = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
			case "multicast-only":
				r.answers = []netip.Addr{netip.MustParseAddr("224.0.0.1")}
			case "overlong-host":
				c.Peers[0].Endpoint.Host = strings.Repeat("x", 254)
			}
			if _, e := Prepare(context.Background(), c, active, roles, r); e == nil {
				t.Fatal("unconfirmed endpoint obtained a fallback")
			}
			if (scenario == "unknown-role" || scenario == "unknown-identity" || scenario == "overlong-host") && r.calls.Load() != 0 {
				t.Fatal("invalid input reached resolver")
			}
		})
	}
}

func TestEndpointResolverReceivesCancellationBeforeAnyUAPIOrUDP(t *testing.T) {
	c := fixtureMember(t)
	active := otherIdentity(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &resolverFixture{block: true, started: make(chan struct{})}
	done := make(chan error, 1)
	go func() { _, e := Prepare(ctx, c, active, Roles{Physical4: 7}, r); done <- e }()
	select {
	case <-r.started:
	case <-time.After(time.Second):
		t.Fatal("resolver did not start")
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancelled resolution returned prepared member")
		}
	case <-time.After(time.Second):
		t.Fatal("resolver did not receive cancellation")
	}
}
