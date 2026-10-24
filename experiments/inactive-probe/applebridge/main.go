//go:build cgo

// SPDX-License-Identifier: MIT
// Experimental archive only. No client VPN start/stop API is exported here.
package main

/*
#include <stdlib.h>
#include "bridge.h"
*/
import "C"

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"unsafe"

	awgprobe "vpn013.local/awg-probe"
)

var ids atomic.Uint64
var drivers sync.Map
var sessions sync.Map

type nativeDriver struct {
	mu        sync.Mutex
	callbacks C.r013_udp_driver
	active    int
	removed   bool
}
type nativeSession struct {
	mu             sync.Mutex
	driver         *nativeDriver
	id             uint64
	deliver        func([]byte)
	failed         func()
	writeID        uint64
	pending        func(error)
	closing        bool
	closed         bool
	closedCallback func()
}

//export R013RegisterUDPDriver
func R013RegisterUDPDriver(callbacks C.r013_udp_driver) C.uint64_t {
	if callbacks.open == nil || callbacks.write == nil || callbacks.cancel == nil || (callbacks.route != 1 && callbacks.route != 2) {
		return 0
	}
	id := ids.Add(1)
	drivers.Store(id, &nativeDriver{callbacks: callbacks})
	return C.uint64_t(id)
}

//export R013UnregisterUDPDriver
func R013UnregisterUDPDriver(driver C.uint64_t) C.int32_t {
	value, ok := drivers.Load(uint64(driver))
	if !ok {
		return 1
	}
	d := value.(*nativeDriver)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.active != 0 {
		return 1
	}
	d.removed = true
	drivers.Delete(uint64(driver))
	return 0
}

func (d *nativeDriver) OpenPhysical(peer netip.AddrPort, deliver func([]byte), failed func()) (awgprobe.PhysicalUDPSession, error) {
	if d.callbacks.route != 1 {
		return nil, awgprobe.ErrPhysicalTransport
	}
	return d.openConnected(peer, deliver, failed)
}

type nativeTunnelFactory struct{ driver *nativeDriver }

func (f nativeTunnelFactory) OpenThroughTunnel(peer netip.AddrPort, deliver func([]byte), failed func()) (awgprobe.ConnectedUDPSession, error) {
	if f.driver.callbacks.route != 2 {
		return nil, awgprobe.ErrPhysicalTransport
	}
	return f.driver.openConnected(peer, deliver, failed)
}

func (d *nativeDriver) openConnected(peer netip.AddrPort, deliver func([]byte), failed func()) (awgprobe.ConnectedUDPSession, error) {
	d.mu.Lock()
	if d.removed || d.active != 0 {
		d.mu.Unlock()
		return nil, awgprobe.ErrPhysicalTransport
	}
	d.active++
	d.mu.Unlock()
	s := &nativeSession{driver: d, id: ids.Add(1), deliver: deliver, failed: failed}
	sessions.Store(s.id, s)
	host := C.CString(peer.Addr().String())
	defer C.free(unsafe.Pointer(host))
	if C.r013_call_open(d.callbacks, C.uint64_t(s.id), host, C.uint16_t(peer.Port())) != 0 {
		// The callback contract guarantees that this failed create owns no
		// platform session. No alternate/default socket is attempted.
		s.didClose()
		return nil, awgprobe.ErrPhysicalTransport
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, awgprobe.ErrPhysicalTransport
	}
	return s, nil
}

func nativeBind(driver uint64, peer netip.AddrPort) (*awgprobe.PhysicalBind, error) {
	value, ok := drivers.Load(driver)
	if !ok {
		return nil, awgprobe.ErrPhysicalTransport
	}
	return awgprobe.NewPhysicalBind(peer, value.(*nativeDriver))
}

func (s *nativeSession) Write(packet []byte, completed func(error)) {
	s.mu.Lock()
	if s.closed || s.closing || s.pending != nil {
		s.mu.Unlock()
		completed(net.ErrClosed)
		return
	}
	s.writeID++
	id := s.writeID
	s.pending = completed
	s.mu.Unlock()
	var memory unsafe.Pointer
	if len(packet) > 0 {
		memory = C.CBytes(packet)
		defer C.free(memory)
	}
	C.r013_call_write(s.driver.callbacks, C.uint64_t(s.id), memory, C.uint32_t(len(packet)), C.uint64_t(id))
}

func (s *nativeSession) Cancel(closed func()) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closed()
		return
	}
	if s.closing {
		s.mu.Unlock()
		return
	}
	s.closing = true
	s.closedCallback = closed
	s.mu.Unlock()
	C.r013_call_cancel(s.driver.callbacks, C.uint64_t(s.id))
}

//export R013UDPDeliver
func R013UDPDeliver(session C.uint64_t, packet unsafe.Pointer, length C.uint32_t) {
	if packet == nil || length == 0 || length > 65535 {
		return
	}
	value, ok := sessions.Load(uint64(session))
	if !ok {
		return
	}
	s := value.(*nativeSession)
	// Hold this narrow lock until the root's bounded synchronous copy has
	// finished, so DidClose cannot acknowledge closure while a read is active.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.closing {
		return
	}
	s.deliver(unsafe.Slice((*byte)(packet), int(length)))
}

//export R013UDPWriteDone
func R013UDPWriteDone(session C.uint64_t, write C.uint64_t, failed C.int32_t) {
	value, ok := sessions.Load(uint64(session))
	if !ok {
		return
	}
	s := value.(*nativeSession)
	s.mu.Lock()
	if s.closed || uint64(write) != s.writeID || s.pending == nil {
		s.mu.Unlock()
		return
	}
	completed := s.pending
	s.pending = nil
	s.mu.Unlock()
	if failed != 0 {
		completed(awgprobe.ErrPhysicalTransport)
	} else {
		completed(nil)
	}
}

//export R013UDPFailed
func R013UDPFailed(session C.uint64_t) {
	value, ok := sessions.Load(uint64(session))
	if !ok {
		return
	}
	s := value.(*nativeSession)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	failed := s.failed
	s.mu.Unlock()
	failed()
}

func (s *nativeSession) didClose() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	closed := s.closedCallback
	pending := s.pending
	s.pending = nil
	s.mu.Unlock()
	sessions.Delete(s.id)
	s.driver.mu.Lock()
	s.driver.active--
	idle := s.driver.active == 0
	s.driver.mu.Unlock()
	if idle {
		C.r013_call_quiesced(s.driver.callbacks)
	}
	if pending != nil {
		pending(net.ErrClosed)
	}
	if closed != nil {
		closed()
	}
}

//export R013UDPDidClose
func R013UDPDidClose(session C.uint64_t) {
	if value, ok := sessions.Load(uint64(session)); ok {
		value.(*nativeSession).didClose()
	}
}

func main() {}
