// SPDX-License-Identifier: MIT
package awgprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsResponseForTest(query []byte) []byte {
	var message dnsmessage.Message
	if err := message.Unpack(query); err != nil {
		return nil
	}
	message.Response = true
	message.RecursionAvailable = true
	message.RCode = dnsmessage.RCodeNameError
	wire, _ := message.Pack()
	return wire
}

func TestDNSChallengeRequiresNonceAndValidDNS(t *testing.T) {
	c, err := newDNSChallenge()
	if err != nil {
		t.Fatal(err)
	}
	valid := dnsResponseForTest(c.wire)
	if !c.valid(valid) {
		t.Fatal("valid NXDOMAIN was rejected")
	}
	for name, change := range map[string]func([]byte) []byte{
		"id":                          func(p []byte) []byte { p[0] ^= 1; return p },
		"request_instead_of_response": func(p []byte) []byte { p[2] &= 0x7f; return p },
		"truncated":                   func(p []byte) []byte { p[2] |= 2; return p },
		"servfail":                    func(p []byte) []byte { p[3] = (p[3] & 0xf0) | 2; return p },
		"foreign_question":            func(p []byte) []byte { p[13] = 'z'; return p },
		"empty_question":              func(p []byte) []byte { p[5] = 0; return p },
		"two_questions":               func(p []byte) []byte { p[5] = 2; return append(p, p[12:]...) },
		"truncated_record":            func(p []byte) []byte { p[7] = 1; return p },
		"compression_loop":            func(p []byte) []byte { p[12] = 0xc0; p[13] = 12; return p },
		"oversized":                   func(p []byte) []byte { return append(p, make([]byte, maxDNSResponse)...) },
	} {
		t.Run(name, func(t *testing.T) {
			if c.valid(change(append([]byte(nil), valid...))) {
				t.Fatal("invalid response accepted")
			}
		})
	}
	other, _ := newDNSChallenge()
	if bytes.Equal(c.wire, other.wire) {
		t.Fatal("challenge reused")
	}
}

type fakeTunnelFactory struct {
	mu        sync.Mutex
	read      func([]byte)
	failed    func()
	delay     time.Duration
	opens     atomic.Int32
	writes    atomic.Int32
	closed    atomic.Int32
	cancelled chan func()
	silent    bool
}

func (f *fakeTunnelFactory) OpenThroughTunnel(_ netip.AddrPort, read func([]byte), failed func()) (ConnectedUDPSession, error) {
	f.mu.Lock()
	f.read = read
	f.failed = failed
	f.mu.Unlock()
	f.opens.Add(1)
	return f, nil
}
func (f *fakeTunnelFactory) Write(p []byte, done func(error)) {
	f.writes.Add(1)
	if f.silent {
		return
	}
	time.Sleep(f.delay)
	f.mu.Lock()
	read := f.read
	f.mu.Unlock()
	read(dnsResponseForTest(p))
	done(nil)
}
func (f *fakeTunnelFactory) Cancel(closed func()) {
	f.closed.Add(1)
	if f.cancelled != nil {
		f.cancelled <- closed
	} else {
		closed()
	}
}

func TestSameDNSMethodForAuthenticatedCandidateAndCurrentPath(t *testing.T) {
	r, peer := fixture(t)
	peer.dns.Store(true)
	peer.delay.Store(int64(15 * time.Millisecond))
	var endpoint netip.AddrPort
	for _, line := range strings.Split(r.Config, "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			endpoint = netip.MustParseAddrPort(strings.TrimPrefix(line, "endpoint="))
		}
	}
	r.Bind, _ = NewPhysicalBind(endpoint, loopbackPhysicalFactory{})
	// A different known primary identity is required; candidate remains excluded
	// if it ever becomes that actual running client/server identity.
	active, _ := fixture(t)
	r.Guard = guardForTest(t, ActiveState{Known: true, Configuration: active.Config})
	candidate, err := MeasureDNS(context.Background(), DNSRequest{Request: r, Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	factory := &fakeTunnelFactory{delay: 15 * time.Millisecond}
	current, err := MeasureCurrentDNS(context.Background(), CurrentDNSRequest{Target: netip.AddrPortFrom(r.Target, 53), Factory: factory, Guard: r.Guard})
	if err != nil || !Comparable(candidate, current) {
		t.Fatal("unlike measurements", candidate, current, err)
	}
	if peer.requests.Load() != 4 || factory.writes.Load() != 4 || factory.opens.Load() != 1 || factory.closed.Load() != 1 {
		t.Fatal("warmup/sample count or socket lifecycle changed")
	}
	if current.Median < 10*time.Millisecond || candidate.Median < 10*time.Millisecond {
		t.Fatal("synthetic delay missing")
	}
	wrong := current
	wrong.Method = "icmp-echo-v1"
	if Comparable(candidate, wrong) {
		t.Fatal("DNS ranked against ICMP")
	}
	wrong = current
	wrong.Target = netip.MustParseAddrPort("10.13.99.1:54")
	if Comparable(candidate, wrong) {
		t.Fatal("different resolver ranked")
	}
	wrong = current
	wrong.Epoch++
	if Comparable(candidate, wrong) {
		t.Fatal("different active epoch ranked")
	}
	t.Logf("Identical UDP/DNS challenge policy: candidate %s, current synthetic path %s; candidate authenticated by AWG; no physical iPhone claim", candidate.Median, current.Median)
}

func TestCurrentDNSCancelsAndDrainsBeforePrimaryTransition(t *testing.T) {
	r, _ := fixture(t)
	guard := guardForTest(t, ActiveState{Known: true, Configuration: r.Config})
	f := &fakeTunnelFactory{silent: true, cancelled: make(chan func(), 1)}
	result := make(chan error, 1)
	go func() {
		_, err := MeasureCurrentDNS(context.Background(), CurrentDNSRequest{Target: netip.AddrPortFrom(r.Target, 53), Factory: f, Guard: guard})
		result <- err
	}()
	deadline := time.Now().Add(time.Second)
	for f.writes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.writes.Load() == 0 {
		t.Fatal("baseline never wrote")
	}
	transition := make(chan *ActiveTransition, 1)
	go func() {
		tr, err := guard.BeginTransition(context.Background())
		if err != nil {
			panic(err)
		}
		transition <- tr
	}()
	ack := <-f.cancelled
	select {
	case <-transition:
		t.Fatal("primary transition raced a live baseline UDP")
	default:
	}
	ack()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal("baseline survived epoch cancellation", err)
	}
	tr := <-transition
	if tr.Commit(ActiveState{Known: true}) != nil {
		t.Fatal("transition failed")
	}
}

func TestCurrentDNSUnknownOrIdleNeverOpensUDP(t *testing.T) {
	for _, state := range []ActiveState{{}, {Known: true}} {
		f := &fakeTunnelFactory{}
		_, err := MeasureCurrentDNS(context.Background(), CurrentDNSRequest{Target: netip.MustParseAddrPort("10.13.99.1:53"), Factory: f, Guard: guardForTest(t, state)})
		if !errors.Is(err, ErrUnknownActiveState) || f.opens.Load() != 0 {
			t.Fatal("unknown/idle primary state opened a socket", err)
		}
	}
}

func TestDNSMemoryRejectsForgedIPPortAndChecksum(t *testing.T) {
	source, target := netip.MustParseAddr("10.13.99.2"), netip.MustParseAddr("10.13.99.1")
	m, _ := newDNSMemory(source, netip.AddrPortFrom(target, 53))
	defer m.Close()
	c, _ := newDNSChallenge()
	payload := dnsResponseForTest(c.wire)
	valid := makeUDPPacket(target, source, 53, m.sourcePort, payload)
	for name, change := range map[string]func([]byte){
		"bad_ip_checksum":  func(p []byte) { p[10] ^= 1 },
		"bad_udp_checksum": func(p []byte) { p[len(p)-1] ^= 1 },
		"wrong_source": func(p []byte) {
			p[15] ^= 1
			binary.BigEndian.PutUint16(p[10:12], 0)
			binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
		},
		"wrong_port":      func(p []byte) { p[21] ^= 1 },
		"fragmented":      func(p []byte) { p[6] |= 0x20 },
		"length_mismatch": func(p []byte) { p[3]-- },
	} {
		t.Run(name, func(t *testing.T) {
			p := append([]byte(nil), valid...)
			change(p)
			m.Write([][]byte{p}, 0)
			if len(m.inbound) != 0 {
				t.Fatal("forged UDP response admitted")
			}
		})
	}
	for i := 0; i < 1000; i++ {
		m.Write([][]byte{valid}, 0)
	}
	if len(m.inbound) != 4 || len(m.slots) != 4 {
		t.Fatal("DNS memory queue not bounded")
	}
}
