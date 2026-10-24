// SPDX-License-Identifier: MIT
package awgprobe

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

func guardForTest(t *testing.T, state ActiveState) *ActiveGuard {
	t.Helper()
	guard, err := NewActiveGuard(state)
	if err != nil {
		t.Fatal(err)
	}
	return guard
}

type delayedCloseBind struct {
	conn.Bind
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
	closed  atomic.Bool
}

func (b *delayedCloseBind) Close() error {
	if b.armed.CompareAndSwap(true, false) {
		close(b.entered)
		<-b.release
		err := b.Bind.Close()
		b.closed.Store(true)
		return err
	}
	return b.Bind.Close()
}

func waitForRequest(t *testing.T, peer *echoResponder) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for peer.requests.Load() == 0 {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("disposable authenticated request did not arrive")
		}
	}
}

func TestPrimaryTransitionWaitsForCandidateUDPToClose(t *testing.T) {
	r, peer := fixture(t)
	peer.delay.Store(int64(300 * time.Millisecond))
	bind := &delayedCloseBind{Bind: r.Bind, entered: make(chan struct{}), release: make(chan struct{})}
	r.Bind = bind
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(bind.release) }) }
	defer release()
	probeDone := make(chan error, 1)
	go func() { _, err := Measure(context.Background(), r); probeDone <- err }()
	waitForRequest(t, peer)
	bind.armed.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	type transitionResult struct {
		token *ActiveTransition
		err   error
	}
	transitionDone := make(chan transitionResult, 1)
	go func() { token, err := r.Guard.BeginTransition(ctx); transitionDone <- transitionResult{token, err} }()
	select {
	case <-bind.entered:
	case <-ctx.Done():
		t.Fatal("candidate shutdown was not reached")
	}
	if _, _, err := r.Guard.acquire(context.Background(), r.Config); !errors.Is(err, ErrUnknownActiveState) {
		t.Fatal("new candidate allowed while the primary change is draining")
	}
	select {
	case <-transitionDone:
		release()
		t.Fatal("primary switch permitted before the candidate UDP transport closed")
	case <-time.After(30 * time.Millisecond):
	}
	release()
	finished := <-transitionDone
	if finished.err != nil || !bind.closed.Load() {
		t.Fatal("transition failed to drain the actual candidate transport")
	}
	if err := <-probeDone; !errors.Is(err, context.Canceled) {
		t.Fatal("primary change did not cancel the ongoing measurement")
	}
	if err := finished.token.Commit(ActiveState{Known: true, Configuration: r.Config}); err != nil {
		t.Fatal(err)
	}
	before := peer.requests.Load()
	if _, err := Measure(context.Background(), r); !errors.Is(err, ErrActiveIdentity) {
		t.Fatal("former candidate could probe its newly active identity")
	}
	if peer.requests.Load() != before {
		t.Fatal("newly active identity received candidate traffic")
	}
}

func TestQueuedCandidateRechecksTheActualNewActiveIdentity(t *testing.T) {
	r, peer := fixture(t)
	permit <- struct{}{}
	held := true
	defer func() {
		if held {
			<-permit
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Measure(ctx, r); done <- err }()
	transition, err := r.Guard.BeginTransition(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := transition.Commit(ActiveState{Known: true, Configuration: r.Config}); err != nil {
		t.Fatal(err)
	}
	<-permit
	held = false
	if err := <-done; !errors.Is(err, ErrActiveIdentity) {
		t.Fatal("queued request used a stale pre-switch identity snapshot")
	}
	if peer.requests.Load() != 0 {
		t.Fatal("queued/newly active identity received plaintext probe traffic")
	}
}

func TestDrainTimeoutLeavesMembershipUnknownUntilExplicitRecovery(t *testing.T) {
	r, _ := fixture(t)
	probeCtx, lease, err := r.Guard.acquire(context.Background(), r.Config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := r.Guard.BeginTransition(ctx); !errors.Is(err, context.DeadlineExceeded) {
		lease.release()
		t.Fatal("incomplete drain must not permit primary activation")
	}
	if !errors.Is(probeCtx.Err(), context.Canceled) {
		t.Fatal("timed-out transition did not cancel its candidate")
	}
	lease.release()
	if _, err := Measure(context.Background(), r); !errors.Is(err, ErrUnknownActiveState) {
		t.Fatal("drain timeout restored a stale active snapshot")
	}
	token, err := r.Guard.BeginTransition(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := token.Commit(ActiveState{Known: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := Measure(context.Background(), r); err != nil {
		t.Fatal("explicit known-state recovery did not re-enable an idle candidate")
	}
}

func TestOldMeasurementsCannotDriveAChangedPrimarySession(t *testing.T) {
	r, _ := fixture(t)
	result, err := Measure(context.Background(), r)
	if err != nil || !r.Guard.Accept(result) {
		t.Fatal("current-epoch measurement was not accepted")
	}
	other, _ := fixture(t)
	token, err := r.Guard.BeginSwitch(context.Background(), result.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if r.Guard.Accept(result) {
		t.Fatal("old result remained eligible during a primary switch")
	}
	if err := token.Commit(ActiveState{Known: true, Configuration: other.Config}); err != nil {
		t.Fatal(err)
	}
	if r.Guard.Accept(result) {
		t.Fatal("old result remained eligible after a primary switch")
	}
	if _, err := r.Guard.BeginSwitch(context.Background(), result.Epoch); !errors.Is(err, ErrStaleEpoch) {
		t.Fatal("stale measurement permitted another primary switch")
	}
	r.Bind = conn.NewStdNetBind()
	fresh, err := Measure(context.Background(), r)
	if err != nil || !r.Guard.Accept(fresh) || fresh.Epoch == result.Epoch {
		t.Fatal("fresh current-epoch measurement did not recover")
	}
}

func TestAbortedAndInvalidCommitsNeverResumeAGuessedIdentity(t *testing.T) {
	r, _ := fixture(t)
	token, err := r.Guard.BeginTransition(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := token.Abort(); err != nil {
		t.Fatal(err)
	}
	if err := token.Abort(); !errors.Is(err, ErrClosedTransition) {
		t.Fatal("completed transition accepted another completion")
	}
	if _, err := Measure(context.Background(), r); !errors.Is(err, ErrUnknownActiveState) {
		t.Fatal("aborted change restored a guessed state")
	}
	token, err = r.Guard.BeginTransition(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := token.Commit(ActiveState{Known: true, Configuration: "invalid"}); !errors.Is(err, ErrUnknownActiveState) {
		t.Fatal("malformed commit accepted")
	}
	if _, err := Measure(context.Background(), r); !errors.Is(err, ErrUnknownActiveState) {
		t.Fatal("malformed commit re-enabled candidate traffic")
	}
}

func TestMissingOrUnknownGuardNeverStartsCandidateTraffic(t *testing.T) {
	for _, name := range []string{"missing", "unknown"} {
		t.Run(name, func(t *testing.T) {
			r, peer := fixture(t)
			r.Guard = nil
			if name == "unknown" {
				r.Guard = guardForTest(t, ActiveState{})
			}
			if _, err := Measure(context.Background(), r); !errors.Is(err, ErrUnknownActiveState) {
				t.Fatal("unconfirmed guard accepted a probe")
			}
			if peer.requests.Load() != 0 {
				t.Fatal("unconfirmed guard opened candidate traffic")
			}
		})
	}
}

func TestPrimaryTransitionsRemainSerializedUntilCompletion(t *testing.T) {
	r, _ := fixture(t)
	first, err := r.Guard.BeginTransition(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Abort()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := r.Guard.BeginTransition(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("another primary transition started before the first was committed")
	}
	if err := first.Commit(ActiveState{Known: true}); err != nil {
		t.Fatal("a canceled waiter invalidated the actual primary transition")
	}
	if _, err := Measure(context.Background(), r); err != nil {
		t.Fatal("serialized transition did not leave the committed state usable")
	}
}
