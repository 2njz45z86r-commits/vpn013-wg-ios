// SPDX-License-Identifier: MIT
package r013prepare

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"golang.org/x/net/dns/dnsmessage"
)

var ErrEndpointDNS = errors.New("explicit endpoint DNS resolution unavailable")

type dnsOpen func(netip.AddrPort, func([]byte), func()) (probe.ConnectedUDPSession, error)

// EndpointResolver uses one explicit protected transport role and one explicit
// resolver. It cannot call the OS/default resolver or fall back to another
// network. Close acknowledgment is genuine, including on deadline cancellation.
type EndpointResolver struct {
	target   netip.AddrPort
	open     dnsOpen
	allow6   bool
	permit   chan struct{}
	mu       sync.Mutex
	lastHost string
	lastTTL  time.Duration
}

func NewTunnelEndpointResolver(target netip.AddrPort, factory probe.TunnelUDPFactory, allow6 bool) (*EndpointResolver, error) {
	if factory == nil {
		return nil, ErrEndpointDNS
	}
	return newEndpointResolver(target, factory.OpenThroughTunnel, allow6)
}
func NewPhysicalEndpointResolver(target netip.AddrPort, factory probe.PhysicalUDPFactory, allow6 bool) (*EndpointResolver, error) {
	if factory == nil {
		return nil, ErrEndpointDNS
	}
	return newEndpointResolver(target, factory.OpenPhysical, allow6)
}
func newEndpointResolver(target netip.AddrPort, open dnsOpen, allow6 bool) (*EndpointResolver, error) {
	if !target.IsValid() || target.Addr().IsUnspecified() || target.Addr().IsMulticast() || target.Port() == 0 || open == nil {
		return nil, ErrEndpointDNS
	}
	return &EndpointResolver{target: target, open: open, allow6: allow6, permit: make(chan struct{}, 1)}, nil
}
func (r *EndpointResolver) TTL(host string) time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastHost != host {
		return 0
	}
	return r.lastTTL
}
func (r *EndpointResolver) LookupNetIP(parent context.Context, network, host string) ([]netip.Addr, error) {
	if parent == nil || parent.Err() != nil || network != "ip" || len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n") {
		return nil, ErrEndpointDNS
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	select {
	case r.permit <- struct{}{}:
		defer func() { <-r.permit }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	r.mu.Lock()
	r.lastHost = ""
	r.lastTTL = 0
	r.mu.Unlock()
	types := []dnsmessage.Type{dnsmessage.TypeA}
	if r.allow6 {
		types = append(types, dnsmessage.TypeAAAA)
	}
	var addresses []netip.Addr
	ttl := 300 * time.Second
	for _, kind := range types {
		found, age, err := r.query(ctx, host, kind)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if len(addresses) > 0 {
				break
			}
			return nil, err
		}
		addresses = append(addresses, found...)
		if age < ttl {
			ttl = age
		}
		if len(addresses) > 16 {
			return nil, ErrEndpointDNS
		}
	}
	if len(addresses) == 0 {
		return nil, ErrEndpointDNS
	}
	r.mu.Lock()
	r.lastHost = host
	r.lastTTL = ttl
	r.mu.Unlock()
	return addresses, nil
}
func (r *EndpointResolver) query(ctx context.Context, host string, kind dnsmessage.Type) ([]netip.Addr, time.Duration, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, 0, ErrEndpointDNS
	}
	var nonce [2]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, 0, ErrEndpointDNS
	}
	request := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(nonce[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}
	wire, err := request.Pack()
	if err != nil {
		return nil, 0, ErrEndpointDNS
	}
	packets := make(chan []byte, 1)
	failed := make(chan struct{})
	var once sync.Once
	session, err := r.open(r.target, func(packet []byte) {
		if len(packet) > 1232 || len(packet) < 12 {
			return
		}
		select {
		case packets <- append([]byte(nil), packet...):
		default:
		}
	}, func() { once.Do(func() { close(failed) }) })
	if session != nil {
		defer func() { closed := make(chan struct{}); session.Cancel(func() { close(closed) }); <-closed }()
	}
	if err != nil || session == nil {
		return nil, 0, ErrEndpointDNS
	}
	written := make(chan error, 1)
	session.Write(wire, func(e error) {
		select {
		case written <- e:
		default:
		}
	})
	select {
	case err = <-written:
		if err != nil {
			return nil, 0, ErrEndpointDNS
		}
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	case <-failed:
		return nil, 0, ErrEndpointDNS
	}
	for {
		select {
		case packet := <-packets:
			var response dnsmessage.Message
			if response.Unpack(packet) != nil || !response.Response || response.Truncated || response.ID != request.ID || len(response.Questions) != 1 || (!strings.EqualFold(response.Questions[0].Name.String(), request.Questions[0].Name.String()) || response.Questions[0].Type != request.Questions[0].Type || response.Questions[0].Class != request.Questions[0].Class) {
				continue
			}
			if response.RCode != dnsmessage.RCodeSuccess || len(response.Answers) > 32 {
				return nil, 0, ErrEndpointDNS
			}
			reachable := map[string]bool{strings.ToLower(name.String()): true}
			ttl := uint32(300)
			for range 8 {
				changed := false
				for _, answer := range response.Answers {
					if answer.Header.Class != dnsmessage.ClassINET || !reachable[strings.ToLower(answer.Header.Name.String())] {
						continue
					}
					if cname, ok := answer.Body.(*dnsmessage.CNAMEResource); ok {
						next := strings.ToLower(cname.CNAME.String())
						if !reachable[next] {
							reachable[next] = true
							changed = true
						}
						if answer.Header.TTL < ttl {
							ttl = answer.Header.TTL
						}
					}
				}
				if !changed {
					break
				}
			}
			var addresses []netip.Addr
			for _, answer := range response.Answers {
				if answer.Header.Class != dnsmessage.ClassINET || !reachable[strings.ToLower(answer.Header.Name.String())] {
					continue
				}
				var ip netip.Addr
				switch body := answer.Body.(type) {
				case *dnsmessage.AResource:
					if kind == dnsmessage.TypeA {
						ip = netip.AddrFrom4(body.A)
					}
				case *dnsmessage.AAAAResource:
					if kind == dnsmessage.TypeAAAA {
						ip = netip.AddrFrom16(body.AAAA)
					}
				}
				if ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() {
					addresses = append(addresses, ip.Unmap())
					if answer.Header.TTL < ttl {
						ttl = answer.Header.TTL
					}
				}
			}
			if len(addresses) > 16 {
				return nil, 0, ErrEndpointDNS
			}
			return addresses, time.Duration(ttl) * time.Second, nil
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-failed:
			return nil, 0, ErrEndpointDNS
		}
	}
}
