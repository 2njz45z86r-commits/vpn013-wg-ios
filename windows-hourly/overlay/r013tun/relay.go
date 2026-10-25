// SPDX-License-Identifier: MIT
// Package r013tun owns a batch-one native TUN while successive, freshly
// initialized engines receive exclusive leases. It does not choose or mutate
// profiles, routes, DNS, firewall policy or the primary lifecycle barrier.
package r013tun

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

const maxPacket = 65535
const queuePackets = 4

var ErrLease = errors.New("exclusive batch-one TUN lease unavailable")

// Relay must be closed by its service owner, after the last engine is retired.
// Closing a Lease never closes the native device. Close waits for real native
// IO and worker completion; a stuck native operation is never acknowledged as
// closed. A generation captured before a blocking Read cannot cross a cutover.
type Relay struct {
	raw       tun.Device
	mu        sync.Mutex
	active    *Lease
	closing   bool
	terminal  error
	writeMu   sync.Mutex
	workers   sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

type Lease struct {
	owner     *Relay
	closed    bool // owner.mu
	done      chan struct{}
	packets   chan []byte
	events    chan tun.Event
	writes    sync.WaitGroup // Add is serialized against closed by owner.mu.
	closeOnce sync.Once
}

func New(raw tun.Device) (*Relay, error) {
	if raw == nil || raw.BatchSize() != 1 {
		return nil, ErrLease
	}
	r := &Relay{raw: raw}
	r.workers.Add(2)
	go r.readLoop()
	go r.eventLoop()
	return r, nil
}

func (r *Relay) Open() (*Lease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.terminal != nil || r.active != nil {
		return nil, ErrLease
	}
	l := &Lease{owner: r, done: make(chan struct{}), packets: make(chan []byte, queuePackets), events: make(chan tun.Event, 8)}
	r.active = l
	return l, nil
}

func (r *Relay) readLoop() {
	defer r.workers.Done()
	buffer := make([]byte, maxPacket)
	sizes := make([]int, 1)
	for {
		r.mu.Lock()
		l, closing := r.active, r.closing
		r.mu.Unlock()
		if closing {
			return
		}
		n, err := r.raw.Read([][]byte{buffer}, sizes, 0)
		if err != nil {
			r.fail(err)
			return
		}
		if n != 1 || sizes[0] < 1 || sizes[0] > len(buffer) {
			r.fail(io.ErrUnexpectedEOF)
			return
		}
		r.mu.Lock()
		if !r.closing && r.active == l && l != nil && !l.closed {
			// At most four queued copies plus one raw buffer. Full queues drop
			// packets, never block native IO or allocate an unbounded backlog.
			if len(l.packets) < cap(l.packets) {
				l.packets <- append([]byte(nil), buffer[:sizes[0]]...)
			}
		}
		r.mu.Unlock()
	}
}

func (r *Relay) eventLoop() {
	defer r.workers.Done()
	for event := range r.raw.Events() {
		if event & ^tun.EventMTUUpdate != 0 {
			r.fail(ErrLease)
			return
		}
		r.mu.Lock()
		if l := r.active; !r.closing && l != nil && !l.closed {
			// This relay is for Windows NativeTun, whose only event is MTU.
			// Refuse an unknown lifecycle event rather than silently drop it.
			select {
			case l.events <- event:
			default:
			}
		}
		r.mu.Unlock()
	}
	r.fail(os.ErrClosed)
}

func (r *Relay) fail(err error) {
	r.mu.Lock()
	if r.terminal == nil {
		r.terminal = err
	}
	if l := r.active; l != nil && !l.closed {
		l.closed = true
		close(l.done)
		close(l.events)
	}
	r.mu.Unlock()
}

func (r *Relay) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closing = true
		l := r.active
		r.mu.Unlock()
		// Native close releases the raw blocking read and any native writes.
		r.closeErr = r.raw.Close()
		if l != nil {
			l.Close()
		}
		r.workers.Wait()
	})
	return r.closeErr
}

func (l *Lease) Close() error {
	l.closeOnce.Do(func() {
		r := l.owner
		r.mu.Lock()
		if !l.closed {
			l.closed = true
			close(l.done)
			close(l.events)
		}
		r.mu.Unlock()
		l.writes.Wait()
		r.mu.Lock()
		// Keep the old lease registered until its last real write has ended.
		if r.active == l {
			r.active = nil
		}
		r.mu.Unlock()
	})
	return nil
}
func (l *Lease) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) < 1 || len(sizes) < 1 || offset < 0 || offset > len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	select {
	case <-l.done:
		return 0, os.ErrClosed
	case packet := <-l.packets:
		r := l.owner
		r.mu.Lock()
		defer r.mu.Unlock()
		if l.closed || r.closing || r.terminal != nil || r.active != l {
			return 0, os.ErrClosed
		}
		if len(bufs[0])-offset < len(packet) {
			return 0, io.ErrShortBuffer
		}
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	}
}
func (l *Lease) Write(bufs [][]byte, offset int) (int, error) {
	if len(bufs) < 1 || len(bufs) > 128 || offset < 0 {
		return 0, io.ErrShortBuffer
	}
	for _, b := range bufs {
		if offset > len(b) || len(b)-offset > maxPacket {
			return 0, io.ErrShortBuffer
		}
	}
	r := l.owner
	r.mu.Lock()
	if l.closed || r.closing || r.terminal != nil || r.active != l {
		r.mu.Unlock()
		return 0, os.ErrClosed
	}
	l.writes.Add(1)
	r.mu.Unlock()
	defer l.writes.Done()
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	r.mu.Lock()
	valid := !l.closed && !r.closing && r.terminal == nil && r.active == l
	r.mu.Unlock()
	if !valid {
		return 0, os.ErrClosed
	}
	return r.raw.Write(bufs, offset)
}
func (l *Lease) File() *os.File           { return l.owner.raw.File() }
func (l *Lease) Name() (string, error)    { return l.owner.raw.Name() }
func (l *Lease) MTU() (int, error)        { return l.owner.raw.MTU() }
func (l *Lease) BatchSize() int           { return 1 }
func (l *Lease) Events() <-chan tun.Event { return l.events }

var _ tun.Device = (*Lease)(nil)
