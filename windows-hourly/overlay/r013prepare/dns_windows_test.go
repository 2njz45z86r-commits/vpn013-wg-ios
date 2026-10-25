// SPDX-License-Identifier: MIT
package r013prepare

import (
	"context"
	"errors"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type endpointDNSFixture struct {
	physical, tunnel, closed atomic.Int32
	wrong                    bool
	hold                     chan struct{}
}
type endpointDNSSession struct {
	fixture *endpointDNSFixture
	deliver func([]byte)
}

func (f *endpointDNSFixture) OpenPhysical(_ netip.AddrPort, deliver func([]byte), _ func()) (probe.PhysicalUDPSession, error) {
	f.physical.Add(1)
	return &endpointDNSSession{f, deliver}, nil
}
func (f *endpointDNSFixture) OpenThroughTunnel(_ netip.AddrPort, deliver func([]byte), _ func()) (probe.ConnectedUDPSession, error) {
	f.tunnel.Add(1)
	return &endpointDNSSession{f, deliver}, nil
}
func (s *endpointDNSSession) Write(packet []byte, done func(error)) {
	var message dnsmessage.Message
	if message.Unpack(packet) != nil || len(message.Questions) != 1 {
		done(ErrEndpointDNS)
		return
	}
	message.Response = true
	if s.fixture.wrong {
		message.ID++
	}
	alias, _ := dnsmessage.NewName("alias.fixture.invalid.")
	foreign, _ := dnsmessage.NewName("foreign.invalid.")
	message.Answers = []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: foreign, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 99}}},
		{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: alias}},
		{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 12}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}}},
	}
	response, _ := message.Pack()
	s.deliver(response)
	done(nil)
}
func (s *endpointDNSSession) Cancel(done func()) {
	if s.fixture.hold != nil {
		<-s.fixture.hold
	}
	s.fixture.closed.Add(1)
	done()
}
func TestExplicitEndpointDNSRoleNonceCNAMEAndTTL(t *testing.T) {
	target := netip.MustParseAddrPort("192.0.2.53:53")
	for _, physical := range []bool{false, true} {
		fixture := &endpointDNSFixture{}
		var resolver *EndpointResolver
		var err error
		if physical {
			resolver, err = NewPhysicalEndpointResolver(target, fixture, false)
		} else {
			resolver, err = NewTunnelEndpointResolver(target, fixture, false)
		}
		if err != nil {
			t.Fatal(err)
		}
		addresses, err := resolver.LookupNetIP(context.Background(), "ip", "Peer.Fixture.Invalid")
		if err != nil || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("192.0.2.7") || resolver.TTL("Peer.Fixture.Invalid") != 12*time.Second {
			t.Fatal("correlated endpoint resolution failed", err)
		}
		if fixture.closed.Load() != 1 || (physical && (fixture.physical.Load() != 1 || fixture.tunnel.Load() != 0)) || (!physical && (fixture.tunnel.Load() != 1 || fixture.physical.Load() != 0)) {
			t.Fatal("role fallback or premature close")
		}
	}
}
func TestEndpointDNSCancellationWaitsForGenuineClose(t *testing.T) {
	fixture := &endpointDNSFixture{wrong: true, hold: make(chan struct{})}
	resolver, _ := NewTunnelEndpointResolver(netip.MustParseAddrPort("192.0.2.53:53"), fixture, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := resolver.LookupNetIP(ctx, "ip", "peer.fixture.invalid"); result <- err }()
	<-ctx.Done()
	select {
	case <-result:
		t.Fatal("resolver acknowledged before actual close")
	case <-time.After(10 * time.Millisecond):
	}
	close(fixture.hold)
	if err := <-result; !errors.Is(err, context.DeadlineExceeded) || fixture.closed.Load() != 1 || resolver.TTL("peer.fixture.invalid") != 0 {
		t.Fatal("forged DNS or cancelled result accepted", err)
	}
}
func TestPrimaryPreparationRemainsSeparateFromCandidateIdentityGuard(t *testing.T) {
	c := fixtureMember(t)
	active, err := Identity(c)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &resolverFixture{answers: []netip.Addr{netip.MustParseAddr("192.0.2.7")}}
	if _, err = Prepare(context.Background(), c, active, Roles{Physical4: 7}, resolver); !errors.Is(err, probe.ErrActiveIdentity) || resolver.calls.Load() != 0 {
		t.Fatal("active candidate alias reached resolver")
	}
	prepared, err := PreparePrimary(context.Background(), c, Roles{Physical4: 7}, resolver)
	if err != nil || prepared.Identity() != active || resolver.calls.Load() != 1 {
		t.Fatal("primary retry preparation failed", err)
	}
	// This helper creates no UDP/engine; Probe ActiveGuard remains mandatory.
}
