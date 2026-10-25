// SPDX-License-Identifier: MIT
// Explicit platform-gated UDP, shared by the Android JNI boundary and tests.
package protectedudp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
)

const Physical = 1
const ThroughTunnel = 2
const maxDatagram = 65535

var ErrRoute = errors.New("explicit platform UDP route unavailable")

// Gate runs on an unconnected socket before connect or any datagram. Android
// must protect physical sockets and bind current sockets to its actual VPN
// Network. A false result never permits a default-route fallback.
type Gate interface {
	Prepare(route int, fd uintptr) error
}

type Factory struct {
	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	gate      Gate
	role      int
	closed    bool
	opening   sync.WaitGroup
	drainOnce sync.Once
	drained   chan struct{}
	live      map[*session]struct{}
	slots     chan struct{}
}

func New(role int, gate Gate) (*Factory, error) {
	if gate == nil || role != Physical && role != ThroughTunnel {
		return nil, ErrRoute
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Factory{ctx: ctx, cancel: cancel, gate: gate, role: role, live: make(map[*session]struct{}), slots: make(chan struct{}, 2), drained: make(chan struct{})}, nil
}

func (f *Factory) OpenPhysical(peer netip.AddrPort, deliver func([]byte), failed func()) (probe.PhysicalUDPSession, error) {
	if f.role != Physical {
		return nil, ErrRoute
	}
	return f.open(peer, deliver, failed)
}
func (f *Factory) OpenThroughTunnel(peer netip.AddrPort, deliver func([]byte), failed func()) (probe.ConnectedUDPSession, error) {
	if f.role != ThroughTunnel {
		return nil, ErrRoute
	}
	return f.open(peer, deliver, failed)
}

func (f *Factory) open(peer netip.AddrPort, deliver func([]byte), failed func()) (probe.ConnectedUDPSession, error) {
	if !peer.IsValid() || peer.Port() == 0 || peer.Addr().IsUnspecified() || peer.Addr().Zone() != "" || deliver == nil || failed == nil {
		return nil, ErrRoute
	}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil, ErrRoute
	}
	select {
	case f.slots <- struct{}{}:
	default:
		f.mu.Unlock()
		return nil, ErrRoute
	}
	f.opening.Add(1)
	f.mu.Unlock()
	defer f.opening.Done()
	owned := false
	defer func() {
		if !owned {
			<-f.slots
		}
	}()
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	dialer := net.Dialer{ControlContext: func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		if ctx.Err() != nil {
			return ErrRoute
		}
		var denied bool
		if raw.Control(func(fd uintptr) { denied = f.gate.Prepare(f.role, fd) != nil }) != nil || denied || ctx.Err() != nil {
			return ErrRoute
		}
		return nil
	}}
	network := "udp6"
	if peer.Addr().Unmap().Is4() {
		network = "udp4"
	}
	connection, err := dialer.DialContext(ctx, network, peer.String())
	if err != nil {
		return nil, ErrRoute
	}
	s := &session{factory: f, conn: connection, readDone: make(chan struct{}), closedDone: make(chan struct{})}
	f.mu.Lock()
	if f.closed || f.ctx.Err() != nil {
		f.mu.Unlock()
		connection.Close()
		return nil, ErrRoute
	}
	f.live[s] = struct{}{}
	owned = true
	f.mu.Unlock()
	go func() {
		defer close(s.readDone)
		packet := make([]byte, maxDatagram)
		for {
			n, err := connection.Read(packet)
			if err != nil {
				if !s.closed.Load() {
					failed()
				}
				return
			}
			if s.closed.Load() || f.ctx.Err() != nil {
				return
			}
			if n > 0 {
				deliver(packet[:n])
			}
		}
	}()
	return s, nil
}

// Invalidate prevents any later socket or write and closes existing descriptors
// immediately. Close additionally waits for in-flight Open/callback completion.
func (f *Factory) Invalidate() {
	f.mu.Lock()
	f.closed = true
	f.cancel()
	live := make([]*session, 0, len(f.live))
	for s := range f.live {
		live = append(live, s)
	}
	f.mu.Unlock()
	for _, s := range live {
		s.stop()
	}
}
func (f *Factory) Close(ctx context.Context) error {
	f.Invalidate()
	f.drainOnce.Do(func() {
		go func() {
			f.opening.Wait()
			f.mu.Lock()
			live := make([]*session, 0, len(f.live))
			for s := range f.live {
				live = append(live, s)
			}
			f.mu.Unlock()
			for _, s := range live {
				s.Cancel(func() {})
			}
			close(f.drained)
		}()
	})
	select {
	case <-f.drained:
		return nil
	case <-ctx.Done():
		return ErrRoute
	}
}

type session struct {
	factory              *Factory
	conn                 net.Conn
	mu                   sync.Mutex
	closed               atomic.Bool
	writing              atomic.Bool
	writes               sync.WaitGroup
	stopOnce, finishOnce sync.Once
	readDone, closedDone chan struct{}
}

func (s *session) Write(packet []byte, completed func(error)) {
	if completed == nil {
		return
	}
	if len(packet) == 0 || len(packet) > maxDatagram || !s.writing.CompareAndSwap(false, true) {
		completed(ErrRoute)
		return
	}
	defer s.writing.Store(false)
	s.mu.Lock()
	if s.closed.Load() || s.factory.ctx.Err() != nil {
		s.mu.Unlock()
		completed(ErrRoute)
		return
	}
	s.writes.Add(1)
	s.mu.Unlock()
	defer s.writes.Done()
	_ = s.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	n, err := s.conn.Write(packet)
	if err != nil || n != len(packet) {
		completed(ErrRoute)
	} else {
		completed(nil)
	}
}
func (s *session) stop() {
	s.stopOnce.Do(func() { s.mu.Lock(); s.closed.Store(true); s.conn.Close(); s.mu.Unlock() })
}
func (s *session) Cancel(closed func()) {
	s.stop()
	s.finishOnce.Do(func() {
		s.writes.Wait()
		<-s.readDone
		s.factory.mu.Lock()
		delete(s.factory.live, s)
		s.factory.mu.Unlock()
		<-s.factory.slots
		close(s.closedDone)
	})
	<-s.closedDone
	if closed != nil {
		closed()
	}
}
