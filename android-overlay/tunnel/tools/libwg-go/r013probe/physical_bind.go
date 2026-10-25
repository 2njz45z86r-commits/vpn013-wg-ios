// SPDX-License-Identifier: MIT
package awgprobe

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

const (
	maxProbeDatagram = 65535
	probeQueueDepth  = 4
)

var ErrPhysicalTransport = errors.New("explicit physical UDP transport unavailable")

// PhysicalUDPFactory MUST create a connected session on the physical interface.
// There is deliberately no default network implementation or fallback. Deliver
// is synchronous and nonblocking; packet bytes are copied before it returns.
// Failure must contain no configuration/key material. Open must not wait for
// network readiness: platform writes report readiness/failure asynchronously.
type PhysicalUDPFactory interface {
	OpenPhysical(peer netip.AddrPort, deliver func([]byte), failed func()) (PhysicalUDPSession, error)
}

// PhysicalUDPSession owns exactly one connected remote endpoint. Write's data
// remains owned by the caller; it must be copied before an asynchronous platform
// API retains it. Completion must occur only after the preceding platform write
// completes. Cancel's callback is stricter: the socket/session must actually be
// closed and its callbacks quiescent. Merely requesting cancellation is not an
// acknowledgement. A missing acknowledgement fails closed and blocks reopening.
type ConnectedUDPSession interface {
	Write(packet []byte, completed func(error))
	Cancel(closed func())
}

// Kept as an alias for the physical factory contract. A current-tunnel factory
// is a separate interface and cannot be substituted for a physical factory.
type PhysicalUDPSession = ConnectedUDPSession

// PhysicalBind implements an actual batch-one transport; it does not wrap
// StdNetBind's platform-dependent 128-packet receive buffers. The fixed connected
// endpoint cannot roam to a different peer or create an unprotected OS socket.
type PhysicalBind struct {
	mu           sync.Mutex
	factory      PhysicalUDPFactory
	peer         netip.AddrPort
	state        *physicalBinding
	writeTimeout time.Duration
}

type physicalBinding struct {
	session    PhysicalUDPSession
	packets    chan []byte
	slots      chan struct{}
	writes     chan struct{}
	done       chan struct{}
	closed     chan struct{}
	stopOnce   sync.Once
	cancelOnce sync.Once
	closedOnce sync.Once
}

// NewPhysicalBind requires an already resolved endpoint and an explicit factory.
// DNS resolution and physical-route selection belong to the platform boundary.
func NewPhysicalBind(peer netip.AddrPort, factory PhysicalUDPFactory) (*PhysicalBind, error) {
	if factory == nil || !peer.IsValid() || peer.Port() == 0 || peer.Addr().IsUnspecified() || peer.Addr().Zone() != "" {
		return nil, ErrPhysicalTransport
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	return &PhysicalBind{peer: peer, factory: factory, writeTimeout: 3 * time.Second}, nil
}

func (*PhysicalBind) BatchSize() int { return 1 }

func (b *PhysicalBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	// NWUDPSession allocates its local port; it cannot implement an arbitrary
	// listen-port request and must never pretend that it did.
	if port != 0 {
		return nil, 0, ErrPhysicalTransport
	}
	s := &physicalBinding{packets: make(chan []byte, probeQueueDepth),
		slots: make(chan struct{}, probeQueueDepth), writes: make(chan struct{}, 1),
		done: make(chan struct{}), closed: make(chan struct{})}
	session, err := b.factory.OpenPhysical(b.peer, s.deliver, func() { s.stop() })
	if err != nil || session == nil {
		s.stop()
		if session != nil {
			session.Cancel(func() { s.closedOnce.Do(func() { close(s.closed) }) })
			<-s.closed
		}
		return nil, 0, ErrPhysicalTransport
	}
	s.session = session
	b.state = s
	return []conn.ReceiveFunc{func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(packets) != 1 || len(sizes) < 1 || len(endpoints) < 1 {
			return 0, io.ErrShortBuffer
		}
		select {
		case <-s.done:
			return 0, net.ErrClosed
		default:
		}
		select {
		case <-s.done:
			return 0, net.ErrClosed
		case packet := <-s.packets:
			defer func() { <-s.slots }()
			select {
			case <-s.done:
				return 0, net.ErrClosed
			default:
			}
			if len(packet) > len(packets[0]) {
				return 0, io.ErrShortBuffer
			}
			sizes[0] = copy(packets[0], packet)
			endpoints[0] = &physicalEndpoint{peer: b.peer, owner: b}
			return 1, nil
		}
	}}, 0, nil
}

func (s *physicalBinding) stop() { s.stopOnce.Do(func() { close(s.done) }) }

func (s *physicalBinding) deliver(packet []byte) {
	if len(packet) == 0 || len(packet) > maxProbeDatagram {
		return
	}
	select {
	case <-s.done:
		return
	default:
	}
	// Acquire capacity BEFORE allocating. Concurrent callbacks cannot turn a
	// four-packet queue into an unbounded set of copied packet allocations.
	select {
	case s.slots <- struct{}{}:
	default:
		return
	}
	owned := append([]byte(nil), packet...)
	select {
	case <-s.done:
		<-s.slots
	case s.packets <- owned:
	}
}

func (b *PhysicalBind) Close() error {
	b.mu.Lock()
	s := b.state
	b.mu.Unlock()
	if s == nil {
		return nil
	}
	s.stop()
	s.cancelOnce.Do(func() {
		s.session.Cancel(func() { s.closedOnce.Do(func() { close(s.closed) }) })
	})
	// ActiveGuard may not permit a primary switch until this real closure
	// acknowledgement arrives. No timeout may pretend the socket is closed.
	<-s.closed
	b.mu.Lock()
	if b.state == s {
		b.state = nil
	}
	b.mu.Unlock()
	return nil
}

func (*PhysicalBind) SetMark(mark uint32) error {
	if mark != 0 {
		return ErrPhysicalTransport
	}
	return nil
}

func (b *PhysicalBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	peer, err := netip.ParseAddrPort(value)
	if err != nil || !peer.IsValid() {
		return nil, ErrPhysicalTransport
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if peer != b.peer {
		return nil, ErrPhysicalTransport
	}
	return &physicalEndpoint{peer: peer, owner: b}, nil
}

func (b *PhysicalBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	ep, ok := endpoint.(*physicalEndpoint)
	if !ok || ep.owner != b || ep.peer != b.peer {
		return conn.ErrWrongEndpointType
	}
	// AWG sends its I1-I5/junk/handshake burst in one call even when the
	// advertised receive batch is1. Preserve the entire burst, writing ONE
	// datagram at a time instead of rejecting or dropping the handshake.
	for _, packet := range packets {
		if len(packet) > maxProbeDatagram {
			return io.ErrShortBuffer
		}
	}
	b.mu.Lock()
	s := b.state
	b.mu.Unlock()
	if s == nil {
		return net.ErrClosed
	}
	select {
	case <-s.done:
		return net.ErrClosed
	case s.writes <- struct{}{}:
	}
	defer func() { <-s.writes }()
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	for _, packet := range packets {
		if err := b.writeOne(s, packet); err != nil {
			return err
		}
	}
	return nil
}

func (b *PhysicalBind) writeOne(s *physicalBinding, packet []byte) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	ack := make(chan error, 1)
	var once sync.Once
	owned := append([]byte(nil), packet...)
	s.session.Write(owned, func(err error) { once.Do(func() { ack <- err }) })
	timer := time.NewTimer(b.writeTimeout)
	defer timer.Stop()
	select {
	case <-s.done:
		return net.ErrClosed
	case <-timer.C:
		s.stop()
		return ErrPhysicalTransport
	case err := <-ack:
		if err != nil {
			s.stop()
			return ErrPhysicalTransport
		}
		return nil
	}
}

type physicalEndpoint struct {
	peer  netip.AddrPort
	owner *PhysicalBind
}

func (*physicalEndpoint) ClearSrc()             {}
func (*physicalEndpoint) SrcToString() string   { return "" }
func (*physicalEndpoint) SrcIP() netip.Addr     { return netip.Addr{} }
func (e *physicalEndpoint) DstIP() netip.Addr   { return e.peer.Addr() }
func (e *physicalEndpoint) DstToString() string { return e.peer.String() }
func (e *physicalEndpoint) DstToBytes() []byte  { value, _ := e.peer.MarshalBinary(); return value }

var _ conn.Bind = (*PhysicalBind)(nil)
