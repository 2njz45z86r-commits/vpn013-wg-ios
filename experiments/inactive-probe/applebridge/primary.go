//go:build cgo

// SPDX-License-Identifier: MIT
package main

/*
#include "bridge.h"
*/
import "C"

import (
	"sync"
	awgprobe "vpn013.local/awg-probe"
)

var primaryGuard, _ = awgprobe.NewActiveGuard(awgprobe.ActiveState{})
var primaryMu sync.Mutex
var primaryTickets = make(map[uint64]func(awgprobe.ActiveState) error)

// Installed only by the merged client's primary implementation. Standalone
// transport tests can never invent a real running device from a saved seed.
var primaryActualRead = func() awgprobe.ActiveState { return awgprobe.ActiveState{} }

//export R013PrimaryBegin
func R013PrimaryBegin() C.uint64_t {
	ctx, cancel := boundedContext()
	defer cancel()
	tr, err := primaryGuard.BeginTransition(ctx)
	if err != nil {
		return 0
	}
	primaryMu.Lock()
	defer primaryMu.Unlock()
	if len(primaryTickets) != 0 {
		_ = tr.Abort()
		return 0
	}
	id := ids.Add(1)
	primaryTickets[id] = tr.Commit
	return C.uint64_t(id)
}

//export R013PrimaryAdopt
func R013PrimaryAdopt(controller C.uint64_t, change C.uint64_t) C.uint64_t {
	c := findController(controller)
	if c == nil {
		return 0
	}
	primaryMu.Lock()
	defer primaryMu.Unlock()
	if len(primaryTickets) != 0 {
		return 0
	}
	finish, err := c.TransferChange(uint64(change))
	if err != nil {
		return 0
	}
	id := ids.Add(1)
	primaryTickets[id] = finish
	return C.uint64_t(id)
}

//export R013PrimaryValidate
func R013PrimaryValidate(ticket C.uint64_t) C.int32_t {
	primaryMu.Lock()
	defer primaryMu.Unlock()
	if ticket == 0 || primaryTickets[uint64(ticket)] == nil {
		return 1
	}
	return 0
}

//export R013PrimaryFinish
func R013PrimaryFinish(ticket C.uint64_t) C.int32_t {
	return finishPrimary(ticket, false)
}

//export R013PrimaryAbort
func R013PrimaryAbort(ticket C.uint64_t) C.int32_t {
	return finishPrimary(ticket, true)
}
func finishPrimary(ticket C.uint64_t, abort bool) C.int32_t {
	primaryMu.Lock()
	finish := primaryTickets[uint64(ticket)]
	if finish == nil {
		primaryMu.Unlock()
		return 1
	}
	delete(primaryTickets, uint64(ticket))
	primaryMu.Unlock()
	actual := awgprobe.ActiveState{}
	if !abort {
		actual = primaryActualRead()
	}
	if finish(actual) != nil {
		return 1
	}
	return 0
}
