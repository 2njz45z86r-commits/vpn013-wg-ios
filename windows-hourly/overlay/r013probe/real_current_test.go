// SPDX-License-Identifier: MIT
package awgprobe

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// A test-only virtual UDP stack attached to ONE real, persistent primary AWG
// engine. Closing a UDP session removes that flow, never the primary device.
// This proves authenticated current/candidate traffic, NOT NEProvider routing.
type realPrimaryUDP struct {
	*memoryTun
	mu     sync.Mutex
	flows  map[uint16]*realPrimaryFlow
	next   uint16
	closed atomic.Int32
}
type realPrimaryFlow struct {
	owner  *realPrimaryUDP
	port   uint16
	mu     sync.Mutex
	closed bool
	read   func([]byte)
}

func (m *realPrimaryUDP) OpenThroughTunnel(target netip.AddrPort, read func([]byte), _ func()) (ConnectedUDPSession, error) {
	if target != netip.AddrPortFrom(m.target, 53) {
		return nil, errors.New("wrong virtual destination")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.flows) >= 3 {
		return nil, errors.New("flow budget")
	}
	m.next++
	f := &realPrimaryFlow{owner: m, port: 50000 + m.next, read: read}
	m.flows[f.port] = f
	return f, nil
}
func (f *realPrimaryFlow) Write(query []byte, done func(error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		done(errors.New("closed virtual flow"))
		return
	}
	packet := makeUDPPacket(f.owner.source, f.owner.target, f.port, 53, query)
	select {
	case f.owner.outbound <- packet:
		done(nil)
	case <-f.owner.done:
		done(errors.New("primary closed"))
	}
}
func (f *realPrimaryFlow) Cancel(done func()) {
	f.mu.Lock()
	f.closed = true
	f.owner.mu.Lock()
	delete(f.owner.flows, f.port)
	f.owner.mu.Unlock()
	f.mu.Unlock()
	done()
}
func (m *realPrimaryUDP) Write(bufs [][]byte, offset int) (int, error) {
	for _, raw := range bufs {
		if offset < 0 || offset+28 > len(raw) {
			continue
		}
		p := raw[offset:]
		port := binary.BigEndian.Uint16(p[22:24])
		payload, ok := parseUDPPacket(p, m.target, m.source, 53, port)
		if !ok {
			continue
		}
		m.mu.Lock()
		flow := m.flows[port]
		m.mu.Unlock()
		if flow == nil {
			continue
		}
		flow.mu.Lock()
		if !flow.closed {
			flow.read(payload)
		}
		flow.mu.Unlock()
	}
	return len(bufs), nil
}
func (m *realPrimaryUDP) Close() error { m.closed.Add(1); return m.memoryTun.Close() }

func TestRealPrimaryDNSContinuesWhileOtherAuthenticatedCandidatesAreScanned(t *testing.T) {
	active, primaryPeer := fixture(t)
	primaryPeer.dns.Store(true)
	primaryPeer.delay.Store(int64(2 * time.Millisecond))
	memory := &realPrimaryUDP{memoryTun: newMemory(active.Source, active.Target), flows: make(map[uint16]*realPrimaryFlow)}
	primary := device.NewDevice(memory, active.Bind, device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(primary.Close)
	if primary.IpcSet(active.Config) != nil || primary.Up() != nil {
		t.Fatal("primary fixture could not start")
	}
	actual, err := primary.IpcGet()
	if err != nil {
		t.Fatal("actual primary runtime unavailable")
	}
	guard, err := NewActiveGuard(ActiveState{Known: true, Configuration: actual})
	if err != nil {
		t.Fatal(err)
	}
	target := netip.AddrPortFrom(active.Target, 53)
	var streamReplies atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamDone := make(chan struct{})
	go func() {
		defer close(streamDone)
		channel := &dnsSessionChannel{packets: make(chan []byte, 4), slots: make(chan struct{}, 4), done: make(chan struct{})}
		session, err := memory.OpenThroughTunnel(target, channel.deliver, channel.stop)
		if err != nil {
			return
		}
		defer closeSession(session)
		for ctx.Err() == nil {
			bound, stop := context.WithTimeout(ctx, time.Second)
			_, err := dnsRoundTrip(bound, func(query []byte) error { return channel.write(bound, session, query) }, channel.packets, channel.done, func() { <-channel.slots })
			stop()
			if err != nil {
				return
			}
			streamReplies.Add(1)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Millisecond):
			}
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for streamReplies.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if streamReplies.Load() == 0 {
		cancel()
		<-streamDone
		t.Fatal("independent primary DNS traffic did not authenticate")
	}
	before := streamReplies.Load()
	candidate := scanCandidateForTest(t, "different-server", guard, time.Millisecond)
	active.Guard = guard
	result, err := Scan(context.Background(), ScanRequest{AutoActive: true, Current: CurrentDNSRequest{Target: target, Factory: memory, Guard: guard},
		Candidates: []ScanCandidate{{ID: "active-must-skip", DNSRequest: DNSRequest{Request: active, Port: 53}}, candidate}})
	after := streamReplies.Load()
	cancel()
	<-streamDone
	if err != nil {
		t.Fatal(err)
	}
	if !Comparable(result.Before, result.After) || result.Before.Method != dnsMethod {
		t.Fatal("current path did not use the identical authenticated DNS method")
	}
	if len(result.Measurements) != 2 || result.Measurements[0].Status != "active_identity_skipped" || result.Measurements[1].Status != "measured" {
		t.Fatal("wrong candidate handling", result.Measurements)
	}
	if after <= before || primaryPeer.requests.Load() < 8 || memory.closed.Load() != 0 {
		t.Fatal("primary stopped or lost its independent traffic during scan", before, after, primaryPeer.requests.Load(), memory.closed.Load())
	}
	t.Logf("Real primary AWG DNS stream %d->%d while another authenticated candidate was measured; primary device remained open", before, after)
}
