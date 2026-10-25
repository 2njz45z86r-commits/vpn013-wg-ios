// SPDX-License-Identifier: MIT
package main

/*
#include <stdlib.h>
#include "r013_android_bridge.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	probe "github.com/amnezia-vpn/amneziawg-android/r013probe"
	"github.com/amnezia-vpn/amneziawg-android/r013probe/protectedudp"
)

var r013Guard, _ = probe.NewActiveGuard(probe.ActiveState{})
var r013IDs atomic.Uint64
var r013PrimaryMu sync.Mutex
var r013Tickets = make(map[uint64]func(probe.ActiveState) error)
var r013ScopesMu sync.Mutex
var r013Scopes = make(map[uint64]*r013Scope)

type r013Scope struct {
	controller        *probe.Controller
	physical, current *protectedudp.Factory
	gate              uint64
	invalid           atomic.Bool
}
type r013Gate struct{ id uint64 }

func (g r013Gate) Prepare(route int, fd uintptr) error {
	if fd > 0x7fffffff || C.r013_gate_prepare(C.uint64_t(g.id), C.int(route), C.int(fd)) != 1 {
		return protectedudp.ErrRoute
	}
	return nil
}
func r013Context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
func r013Find(id uint64) *r013Scope {
	r013ScopesMu.Lock()
	defer r013ScopesMu.Unlock()
	return r013Scopes[id]
}
func (s *r013Scope) invalidate() {
	s.invalid.Store(true)
	s.physical.Invalidate()
	s.current.Invalidate()
}
func r013InvalidateScopes() {
	r013ScopesMu.Lock()
	defer r013ScopesMu.Unlock()
	for _, s := range r013Scopes {
		s.invalidate()
	}
}

// The primary registry is observed, not supplied by a saved/seed configuration.
func r013Actual() probe.ActiveState {
	tunnelHandlesMu.RLock()
	defer tunnelHandlesMu.RUnlock()
	if len(tunnelHandles) == 0 {
		return probe.ActiveState{Known: true}
	}
	if len(tunnelHandles) != 1 {
		return probe.ActiveState{}
	}
	for _, h := range tunnelHandles {
		wire, e := h.device.IpcGet()
		if e != nil {
			return probe.ActiveState{}
		}
		return probe.ActiveState{Known: true, Configuration: wire}
	}
	return probe.ActiveState{}
}
func r013Valid(ticket uint64) bool {
	r013PrimaryMu.Lock()
	defer r013PrimaryMu.Unlock()
	return ticket != 0 && r013Tickets[ticket] != nil
}

//export r013PrimaryBegin
func r013PrimaryBegin() C.longlong {
	r013InvalidateScopes()
	ctx, cancel := r013Context()
	defer cancel()
	transition, e := r013Guard.BeginTransition(ctx)
	if e != nil {
		return 0
	}
	r013PrimaryMu.Lock()
	defer r013PrimaryMu.Unlock()
	if len(r013Tickets) != 0 {
		transition.Abort()
		return 0
	}
	id := r013IDs.Add(1)
	r013Tickets[id] = transition.Commit
	return C.longlong(id)
}

//export r013PrimaryEnd
func r013PrimaryEnd(ticket C.longlong) C.int {
	r013PrimaryMu.Lock()
	finish := r013Tickets[uint64(ticket)]
	delete(r013Tickets, uint64(ticket))
	r013PrimaryMu.Unlock()
	if finish == nil {
		return 1
	}
	if finish(r013Actual()) != nil {
		return 1
	}
	return 0
}

//export r013ProbeCreate
func r013ProbeCreate(gate C.longlong) C.longlong {
	if gate <= 0 {
		return 0
	}
	r013ScopesMu.Lock()
	defer r013ScopesMu.Unlock()
	if len(r013Scopes) >= 2 {
		return 0
	}
	physical, e := protectedudp.New(protectedudp.Physical, r013Gate{uint64(gate)})
	if e != nil {
		return 0
	}
	current, e := protectedudp.New(protectedudp.ThroughTunnel, r013Gate{uint64(gate)})
	if e != nil {
		return 0
	}
	c, e := probe.NewControllerWithGuard(physical, current, r013Guard)
	if e != nil {
		return 0
	}
	id := r013IDs.Add(1)
	r013Scopes[id] = &r013Scope{controller: c, physical: physical, current: current, gate: uint64(gate)}
	return C.longlong(id)
}

//export r013ProbeInvalidate
func r013ProbeInvalidate(id C.longlong) {
	if s := r013Find(uint64(id)); s != nil {
		s.invalidate()
	}
}

//export r013ProbeRefresh
func r013ProbeRefresh(id C.longlong) C.int {
	s := r013Find(uint64(id))
	if s == nil || s.invalid.Load() {
		return 1
	}
	ctx, cancel := r013Context()
	defer cancel()
	token, e := s.controller.BeginChange(ctx)
	if e != nil {
		return 1
	}
	if s.controller.CommitChange(token, r013Actual()) != nil || s.invalid.Load() {
		return 1
	}
	return 0
}

func r013Input(raw *C.char, length C.int) (probe.ScanInput, bool) {
	if raw == nil || length <= 0 || length > probe.MaxScanJSON {
		return probe.ScanInput{}, false
	}
	wire := unsafe.Slice((*byte)(unsafe.Pointer(raw)), int(length))
	in, e := probe.DecodeScanInput(wire)
	return in, e == nil
}

//export r013ProbeStart
func r013ProbeStart(id C.longlong, raw *C.char, length C.int) C.longlong {
	s := r013Find(uint64(id))
	if s == nil || s.invalid.Load() {
		return 0
	}
	in, ok := r013Input(raw, length)
	if !ok {
		return 0
	}
	op, e := s.controller.StartScan(in)
	if e != nil {
		return 0
	}
	return C.longlong(op)
}

//export r013ProbePoll
func r013ProbePoll(id, operation C.longlong) *C.char {
	s := r013Find(uint64(id))
	if s == nil || s.invalid.Load() {
		return nil
	}
	status, e := s.controller.PollScan(uint64(operation))
	if e != nil {
		return nil
	}
	wire, e := json.Marshal(status)
	if e != nil || len(wire) > 65536 {
		return nil
	}
	return C.CString(string(wire))
}

//export r013ProbeChoose
func r013ProbeChoose(id, operation C.longlong, raw *C.char, length C.int) C.longlong {
	s := r013Find(uint64(id))
	if s == nil || s.invalid.Load() {
		return 0
	}
	fresh, ok := r013Input(raw, length)
	if !ok || len(fresh.Candidates) != 1 {
		return 0
	}
	ctx, cancel := r013Context()
	defer cancel()
	change, e := s.controller.BeginChoice(ctx, uint64(operation), fresh.Candidates[0], fresh.Resolver)
	if e != nil {
		return 0
	}
	finish, e := s.controller.TransferChange(change)
	if e != nil {
		return 0
	}
	r013PrimaryMu.Lock()
	defer r013PrimaryMu.Unlock()
	if s.invalid.Load() || len(r013Tickets) != 0 {
		_ = finish(probe.ActiveState{})
		return 0
	}
	ticket := r013IDs.Add(1)
	r013Tickets[ticket] = finish
	return C.longlong(ticket)
}

//export r013ProbeRelease
func r013ProbeRelease(id C.longlong) C.int {
	s := r013Find(uint64(id))
	if s == nil {
		return 1
	}
	s.invalidate()
	ctx, cancel := r013Context()
	defer cancel()
	if s.controller.Close(ctx) != nil || s.physical.Close(ctx) != nil || s.current.Close(ctx) != nil {
		return 1
	}
	r013ScopesMu.Lock()
	if r013Scopes[uint64(id)] == s {
		delete(r013Scopes, uint64(id))
	}
	r013ScopesMu.Unlock()
	C.r013_gate_release(C.uint64_t(s.gate))
	return 0
}

//export awgTurnOnGuarded
func awgTurnOnGuarded(ticket C.longlong, interfaceName string, tunFd int32, settings string) int32 {
	r013PrimaryMu.Lock()
	defer r013PrimaryMu.Unlock()
	if ticket <= 0 || r013Tickets[uint64(ticket)] == nil {
		unix.Close(int(tunFd))
		return -1
	}
	return awgTurnOnInternal(interfaceName, tunFd, settings)
}

//export awgTurnOffGuarded
func awgTurnOffGuarded(ticket C.longlong, handle int32) C.int {
	r013PrimaryMu.Lock()
	defer r013PrimaryMu.Unlock()
	if ticket <= 0 || r013Tickets[uint64(ticket)] == nil {
		return 1
	}
	awgTurnOffInternal(handle)
	return 0
}

//export awgGetInterfaceName
func awgGetInterfaceName(handle int32) *C.char {
	tunnelHandlesMu.RLock()
	defer tunnelHandlesMu.RUnlock()
	h, ok := tunnelHandles[handle]
	if !ok {
		return nil
	}
	return C.CString(h.name)
}
