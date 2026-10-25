// SPDX-License-Identifier: MIT
// DNS framing/validation: https://www.rfc-editor.org/rfc/rfc1035 sections4.1/4.2.1.
package awgprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsMethod = "dns-udp-challenge-v1"
const maxDNSResponse = 1232

// DNSRequest uses the same explicit resolver address/port for EVERY compared
// result. No system resolver, OS DNS settings, public fallback or user domains
// are used. A timeout means this measurement is unavailable, not a failed VPN.
type DNSRequest struct {
	Request
	Port uint16
}

func MeasureDNS(ctx context.Context, r DNSRequest) (Result, error) {
	if r.Port == 0 {
		return Result{}, errors.New("explicit DNS port required")
	}
	return measureCandidate(ctx, r.Request, func() (samplingTun, error) {
		return newDNSMemory(r.Source, netip.AddrPortFrom(r.Target, r.Port))
	}, dnsMethod, netip.AddrPortFrom(r.Target, r.Port))
}

// TunnelUDPFactory must create a connected socket THROUGH the current virtual
// interface, not a fresh AWG engine or a physical/default socket. Platform route
// selection is separately verified before integration; there is no fallback.
type TunnelUDPFactory interface {
	OpenThroughTunnel(netip.AddrPort, func([]byte), func()) (ConnectedUDPSession, error)
}
type CurrentDNSRequest struct {
	Target  netip.AddrPort
	Factory TunnelUDPFactory
	Guard   *ActiveGuard
}

func MeasureCurrentDNS(parent context.Context, r CurrentDNSRequest) (Result, error) {
	if r.Guard == nil {
		return Result{}, ErrUnknownActiveState
	}
	if r.Factory == nil || !r.Target.IsValid() || !r.Target.Addr().Is4() || r.Target.Addr().IsUnspecified() || r.Target.Port() == 0 {
		return Result{}, errors.New("explicit through-tunnel UDP factory and IPv4 resolver required")
	}
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	select {
	case permit <- struct{}{}:
		defer func() { <-permit }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}
	ctx, lease, err := r.Guard.acquireBaseline(ctx)
	if err != nil {
		return Result{}, err
	}
	defer lease.release()
	channel := &dnsSessionChannel{packets: make(chan []byte, 4), slots: make(chan struct{}, 4), done: make(chan struct{})}
	session, err := r.Factory.OpenThroughTunnel(r.Target, channel.deliver, channel.stop)
	if err != nil || session == nil {
		channel.stop()
		if session != nil {
			closeSession(session)
		}
		return Result{}, errors.New("current-tunnel UDP transport unavailable")
	}
	// Lease release MUST occur after the platform confirms actual UDP closure.
	defer func() { channel.stop(); closeSession(session) }()
	return collectSamples(ctx, func(ctx context.Context) (time.Duration, error) {
		return dnsRoundTrip(ctx, func(query []byte) error { return channel.write(ctx, session, query) }, channel.packets, channel.done, func() { <-channel.slots })
	}, lease.epoch, dnsMethod, r.Target, r.Guard)
}

func closeSession(session ConnectedUDPSession) {
	done := make(chan struct{})
	var once sync.Once
	session.Cancel(func() { once.Do(func() { close(done) }) })
	<-done
}

type dnsSessionChannel struct {
	packets chan []byte
	slots   chan struct{}
	done    chan struct{}
	once    sync.Once
}

func (c *dnsSessionChannel) stop() { c.once.Do(func() { close(c.done) }) }
func (c *dnsSessionChannel) deliver(p []byte) {
	if len(p) < 12 || len(p) > maxDNSResponse {
		return
	}
	select {
	case <-c.done:
		return
	default:
	}
	select {
	case c.slots <- struct{}{}:
	default:
		return
	}
	owned := append([]byte(nil), p...)
	select {
	case <-c.done:
		<-c.slots
	case c.packets <- owned:
	}
}
func (c *dnsSessionChannel) write(ctx context.Context, session ConnectedUDPSession, p []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return errors.New("current UDP session closed")
	default:
	}
	ack := make(chan error, 1)
	var once sync.Once
	session.Write(p, func(err error) { once.Do(func() { ack <- err }) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return errors.New("current UDP session closed")
	case err := <-ack:
		return err
	}
}

type dnsChallenge struct {
	wire     []byte
	id       uint16
	question dnsmessage.Question
}

func newDNSChallenge() (dnsChallenge, error) {
	var nonce [18]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return dnsChallenge{}, err
	}
	name, err := dnsmessage.NewName(hex.EncodeToString(nonce[2:]) + ".r013.invalid.")
	if err != nil {
		return dnsChallenge{}, err
	}
	q := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	id := binary.BigEndian.Uint16(nonce[:2])
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{q}}
	wire, err := m.Pack()
	return dnsChallenge{wire: wire, id: id, question: q}, err
}
func (c dnsChallenge) valid(packet []byte) bool {
	if len(packet) > maxDNSResponse {
		return false
	}
	var p dnsmessage.Parser
	header, err := p.Start(packet)
	if err != nil || header.ID != c.id || !header.Response || header.Truncated || header.OpCode != 0 ||
		(header.RCode != dnsmessage.RCodeSuccess && header.RCode != dnsmessage.RCodeNameError) {
		return false
	}
	q, err := p.Question()
	if err != nil || q != c.question {
		return false
	}
	if _, err = p.Question(); err != dnsmessage.ErrSectionDone {
		return false
	}
	return p.SkipAllAnswers() == nil && p.SkipAllAuthorities() == nil && p.SkipAllAdditionals() == nil
}

func dnsRoundTrip(ctx context.Context, send func([]byte) error, replies <-chan []byte, done <-chan struct{}, consumed func()) (time.Duration, error) {
	challenge, err := newDNSChallenge()
	if err != nil {
		return 0, err
	}
	started := time.Now()
	if err = send(challenge.wire); err != nil {
		return 0, err
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-done:
			return 0, errors.New("DNS probe transport closed")
		case <-ticker.C:
			if err = send(challenge.wire); err != nil {
				return 0, err
			}
		case reply := <-replies:
			if consumed != nil {
				consumed()
			}
			if challenge.valid(reply) {
				return time.Since(started), nil
			}
		}
	}
}

type dnsMemory struct {
	*memoryTun
	resolver   netip.AddrPort
	sourcePort uint16
	slots      chan struct{}
}

func newDNSMemory(source netip.Addr, resolver netip.AddrPort) (*dnsMemory, error) {
	var entropy [2]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, err
	}
	return &dnsMemory{memoryTun: newMemory(source, resolver.Addr()), resolver: resolver, sourcePort: 49152 + binary.BigEndian.Uint16(entropy[:])%16384, slots: make(chan struct{}, 4)}, nil
}
func (m *dnsMemory) sample(ctx context.Context) (time.Duration, error) {
	return dnsRoundTrip(ctx, func(query []byte) error {
		packet := makeUDPPacket(m.source, m.target, m.sourcePort, m.resolver.Port(), query)
		select {
		case m.outbound <- packet:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-m.done:
			return errors.New("DNS memory TUN closed")
		}
	}, m.inbound, m.done, func() { <-m.slots })
}
func (m *dnsMemory) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if offset < 0 || offset > len(b) {
			continue
		}
		p := b[offset:]
		payload, ok := parseUDPPacket(p, m.target, m.source, m.resolver.Port(), m.sourcePort)
		if !ok || len(payload) < 12 || len(payload) > maxDNSResponse {
			continue
		}
		select {
		case <-m.done:
			return 0, errors.New("DNS memory TUN closed")
		default:
		}
		select {
		case m.slots <- struct{}{}:
		default:
			continue
		}
		owned := append([]byte(nil), payload...)
		select {
		case m.inbound <- owned:
		case <-m.done:
			<-m.slots
		}
	}
	return len(bufs), nil
}

func makeUDPPacket(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte) []byte {
	p := make([]byte, 28+len(payload))
	p[0] = 0x45
	p[8] = 64
	p[9] = 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	src, dst := source.As4(), target.As4()
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], sourcePort)
	binary.BigEndian.PutUint16(p[22:24], targetPort)
	binary.BigEndian.PutUint16(p[24:26], uint16(len(p)-20))
	copy(p[28:], payload)
	value := udpChecksum(p[12:20], p[20:])
	if value == 0 {
		value = 65535
	}
	binary.BigEndian.PutUint16(p[26:28], value)
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	return p
}
func parseUDPPacket(p []byte, source, target netip.Addr, sourcePort, targetPort uint16) ([]byte, bool) {
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
		return nil, false
	}
	ihl := int(p[0]&15) * 4
	if ihl < 20 || ihl+8 > len(p) || checksum(p[:ihl]) != 0 {
		return nil, false
	}
	src, dst := source.As4(), target.As4()
	if string(p[12:16]) != string(src[:]) || string(p[16:20]) != string(dst[:]) {
		return nil, false
	}
	u := p[ihl:]
	if binary.BigEndian.Uint16(u[:2]) != sourcePort || binary.BigEndian.Uint16(u[2:4]) != targetPort || int(binary.BigEndian.Uint16(u[4:6])) != len(u) {
		return nil, false
	}
	if binary.BigEndian.Uint16(u[6:8]) != 0 && udpChecksum(p[12:20], u) != 0 {
		return nil, false
	}
	return u[8:], true
}
func udpChecksum(addresses, udp []byte) uint16 {
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo, addresses)
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	copy(pseudo[12:], udp)
	return checksum(pseudo)
}
