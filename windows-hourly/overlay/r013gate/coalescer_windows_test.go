// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestRouteWorkerCloseDrainsKernelWaitWhileCallerOwnsPrimary(t *testing.T) {
	requireCI(t)
	gate := testGate(t, testName(t))
	var ran atomic.Uint32
	worker, err := NewCoalescer(context.Background(), gate, time.Millisecond, 3*time.Millisecond, func() error { ran.Add(1); return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	err = gate.Primary(context.Background(), Stamp{}, func(context.Context) error {
		worker.Notify()
		time.Sleep(15 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return worker.Close(ctx) // must cancel the worker's wait, not deadlock on us
	})
	if err != nil {
		t.Fatal(err)
	}
	if ran.Load() != 0 {
		t.Fatal("cancelled callback mutated after watcher teardown")
	}
	worker.Notify()
	time.Sleep(5 * time.Millisecond)
	if ran.Load() != 0 {
		t.Fatal("closed worker accepted another path event")
	}
}
func TestRouteNotificationInvalidatesImmediatelyAndBurstIsBounded(t *testing.T) {
	requireCI(t)
	gate := testGate(t, testName(t))
	ready := make(chan Token, 1)
	cancelled := make(chan struct{})
	finish := make(chan error, 1)
	go func() {
		finish <- gate.Candidate(context.Background(), func(ctx context.Context, token Token) error {
			ready <- token
			<-ctx.Done()
			close(cancelled)
			return nil
		})
	}()
	token := <-ready
	var ran atomic.Uint32
	executed := make(chan struct{}, 4)
	worker, err := NewCoalescer(context.Background(), gate, 20*time.Millisecond, 60*time.Millisecond, func() error {
		ran.Add(1)
		select {
		case executed <- struct{}{}:
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close(context.Background())
	worker.Notify()
	if token.Valid() {
		t.Fatal("path event waited for debounce before invalidating")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("path event did not cancel candidate")
	}
	if err := <-finish; err != nil {
		t.Fatal(err)
	}
	stop := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(stop) {
		worker.Notify()
		time.Sleep(3 * time.Millisecond)
	}
	select {
	case <-executed:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("continuous notifications starved the maximum burst deadline")
	}
	if err = worker.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	count := ran.Load()
	time.Sleep(30 * time.Millisecond)
	if ran.Load() != count {
		t.Fatal("queued timer survived close")
	}
	if count > 3 {
		t.Fatal("unbounded catch-up callback storm")
	}
}
