//go:build cgo

// SPDX-License-Identifier: MIT
package main

/*
#include "bridge.h"
*/
import "C"

import (
	"context"
	"encoding/json"
	"sync"
	"time"
	"unsafe"

	awgprobe "vpn013.local/awg-probe"
)

// One extension process owns at most two controllers during handover. Each
// owns one scan/transition, so hostile/stale callers cannot grow a handle map.
var controllerLock sync.Mutex
var controllers = make(map[uint64]*awgprobe.Controller)

func findController(id C.uint64_t) *awgprobe.Controller {
	controllerLock.Lock()
	defer controllerLock.Unlock()
	return controllers[uint64(id)]
}
func boundedContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
func inputBytes(raw unsafe.Pointer, length C.uint32_t, maximum int) ([]byte, bool) {
	if raw == nil || length == 0 || uint64(length) > uint64(maximum) {
		return nil, false
	}
	// This view is valid only during the synchronous C call. JSON decoding/string
	// construction below makes owned copies before any asynchronous scan starts.
	return unsafe.Slice((*byte)(raw), int(length)), true
}

//export R013ProbeCreate
func R013ProbeCreate(physicalID C.uint64_t, currentID C.uint64_t) C.uint64_t {
	pv, pok := drivers.Load(uint64(physicalID))
	cv, cok := drivers.Load(uint64(currentID))
	if !pok || !cok || pv.(*nativeDriver).callbacks.route != 1 || cv.(*nativeDriver).callbacks.route != 2 {
		return 0
	}
	controllerLock.Lock()
	defer controllerLock.Unlock()
	if len(controllers) >= 2 {
		return 0
	}
	c, err := awgprobe.NewControllerWithGuard(pv.(*nativeDriver), nativeTunnelFactory{cv.(*nativeDriver)}, primaryGuard)
	if err != nil {
		return 0
	}
	id := ids.Add(1)
	controllers[id] = c
	return C.uint64_t(id)
}

//export R013ProbeBeginChange
func R013ProbeBeginChange(id C.uint64_t) C.uint64_t {
	c := findController(id)
	if c == nil {
		return 0
	}
	ctx, cancel := boundedContext()
	defer cancel()
	change, err := c.BeginChange(ctx)
	if err != nil {
		return 0
	}
	return C.uint64_t(change)
}

//export R013ProbeCommitChange
func R013ProbeCommitChange(id C.uint64_t, change C.uint64_t, known C.int32_t, raw unsafe.Pointer, length C.uint32_t) C.int32_t {
	c := findController(id)
	if c == nil {
		return 1
	}
	state := awgprobe.ActiveState{}
	if known == 1 {
		if length == 0 {
			state.Known = true
		} else if wire, ok := inputBytes(raw, length, 1024*1024); ok {
			state.Known, state.Configuration = true, string(wire)
		} // Invalid input is deliberately committed as UNKNOWN, not previous state.
	}
	if c.CommitChange(uint64(change), state) != nil {
		return 1
	}
	if known != 0 && known != 1 || known == 1 && length != 0 && !state.Known {
		return 1
	}
	return 0
}

//export R013ProbeStartScan
func R013ProbeStartScan(id C.uint64_t, raw unsafe.Pointer, length C.uint32_t) C.uint64_t {
	c := findController(id)
	if c == nil {
		return 0
	}
	wire, ok := inputBytes(raw, length, awgprobe.MaxScanJSON)
	if !ok {
		return 0
	}
	in, err := awgprobe.DecodeScanInput(wire)
	if err != nil {
		return 0
	}
	op, err := c.StartScan(in)
	if err != nil {
		return 0
	}
	return C.uint64_t(op)
}

//export R013ProbePollScan
func R013ProbePollScan(id C.uint64_t, operation C.uint64_t, raw unsafe.Pointer, capacity C.uint32_t) C.int32_t {
	c := findController(id)
	if c == nil {
		return -1
	}
	status, err := c.PollScan(uint64(operation))
	if err != nil {
		return -1
	}
	wire, err := json.Marshal(status)
	if err != nil || len(wire) > 64*1024 || raw == nil || capacity > 64*1024 || uint64(capacity) < uint64(len(wire)) {
		return -1
	}
	copy(unsafe.Slice((*byte)(raw), int(capacity)), wire)
	return C.int32_t(len(wire)) // Exact byte length, no trailing NUL or keys.
}

//export R013ProbeCancelScan
func R013ProbeCancelScan(id C.uint64_t, operation C.uint64_t) C.int32_t {
	c := findController(id)
	if c == nil {
		return 1
	}
	ctx, cancel := boundedContext()
	defer cancel()
	if c.CancelScan(ctx, uint64(operation)) != nil {
		return 1
	}
	return 0
}

//export R013ProbeBeginChoice
func R013ProbeBeginChoice(id C.uint64_t, operation C.uint64_t, raw unsafe.Pointer, length C.uint32_t) C.uint64_t {
	c := findController(id)
	if c == nil {
		return 0
	}
	wire, ok := inputBytes(raw, length, awgprobe.MaxScanJSON)
	if !ok {
		return 0
	}
	fresh, err := awgprobe.DecodeScanInput(wire)
	if err != nil || len(fresh.Candidates) != 1 {
		return 0
	}
	ctx, cancel := boundedContext()
	defer cancel()
	change, err := c.BeginChoice(ctx, uint64(operation), fresh.Candidates[0], fresh.Resolver)
	if err != nil {
		return 0
	}
	return C.uint64_t(change)
}

//export R013ProbeRelease
func R013ProbeRelease(id C.uint64_t) C.int32_t {
	c := findController(id)
	if c == nil {
		return 1
	}
	ctx, cancel := boundedContext()
	defer cancel()
	if c.Close(ctx) != nil {
		return 1
	}
	controllerLock.Lock()
	delete(controllers, uint64(id))
	controllerLock.Unlock()
	// A predecessor provider may be released after a successor starts. Restore
	// only the observed process registry, never the predecessor's saved identity.
	if tr, err := primaryGuard.BeginTransition(ctx); err == nil {
		_ = tr.Commit(primaryActualRead())
	}
	return 0
}
