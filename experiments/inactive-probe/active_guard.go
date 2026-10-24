// SPDX-License-Identifier: MIT
package awgprobe

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var ErrStaleEpoch = errors.New("measurement belongs to an earlier active session")
var ErrClosedTransition = errors.New("active transition is already finished")

// ActiveGuard fences candidate engines against changes to the real running
// identity. The caller MUST acquire a transition and wait for it to return
// before starting/updating/stopping the primary engine, then commit its actual
// state. No platform adapter is connected to this experimental API yet.
// Only a public identity digest is retained, never a configuration/private key.
type ActiveGuard struct {
	mu         sync.Mutex
	transition chan struct{}
	epoch      uint64
	known      bool
	hasPeer    bool
	identity   [32]byte
	blocked    bool
	live       map[*probeLease]struct{}
}

func NewActiveGuard(initial ActiveState) (*ActiveGuard, error) {
	known, peer, id, err := activeIdentity(initial)
	if err != nil {
		return nil, err
	}
	return &ActiveGuard{transition: make(chan struct{}, 1), epoch: 1, known: known,
		hasPeer: peer, identity: id, live: make(map[*probeLease]struct{})}, nil
}

func activeIdentity(state ActiveState) (bool, bool, [32]byte, error) {
	var none [32]byte
	if !state.Known {
		return false, false, none, nil
	}
	if state.Configuration == "" {
		return true, false, none, nil
	}
	id, err := peerIdentity(state.Configuration)
	if err != nil {
		return false, false, none, ErrUnknownActiveState
	}
	return true, true, id, nil
}

type probeLease struct {
	guard  *ActiveGuard
	epoch  uint64
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func (g *ActiveGuard) acquire(parent context.Context, configuration string) (context.Context, *probeLease, error) {
	if err := parent.Err(); err != nil {
		return nil, nil, err
	}
	id, err := peerIdentity(configuration)
	if err != nil {
		return nil, nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.known || g.blocked {
		return nil, nil, ErrUnknownActiveState
	}
	if g.hasPeer && id == g.identity {
		return nil, nil, ErrActiveIdentity
	}
	ctx, cancel := context.WithCancel(parent)
	lease := &probeLease{guard: g, epoch: g.epoch, cancel: cancel, done: make(chan struct{})}
	g.live[lease] = struct{}{}
	return ctx, lease, nil
}

func (lease *probeLease) release() {
	lease.once.Do(func() {
		lease.cancel()
		g := lease.guard
		g.mu.Lock()
		delete(g.live, lease)
		close(lease.done)
		g.mu.Unlock()
	})
}

// Accept must be checked again before displaying/ranking delayed results. A
// switch decision uses BeginSwitch so this check and invalidation are atomic.
func (g *ActiveGuard) Accept(result Result) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.known && !g.blocked && result.Epoch == g.epoch && result.Samples == 3 && result.Median >= 0
}

type ActiveTransition struct {
	guard *ActiveGuard
	epoch uint64
	done  atomic.Bool
}

// BeginTransition blocks new candidates, cancels old ones and waits until every
// candidate's engine/UDP transport has closed. An error is NOT permission to
// change the primary engine. A drain timeout leaves membership unknown; an
// explicit later successful transition is required to enable probes again.
func (g *ActiveGuard) BeginTransition(ctx context.Context) (*ActiveTransition, error) {
	return g.begin(ctx, 0, false)
}

func (g *ActiveGuard) BeginSwitch(ctx context.Context, measuredEpoch uint64) (*ActiveTransition, error) {
	return g.begin(ctx, measuredEpoch, true)
}

func (g *ActiveGuard) begin(ctx context.Context, expected uint64, requireEpoch bool) (*ActiveTransition, error) {
	select {
	case g.transition <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-g.transition
		return nil, err
	}
	g.mu.Lock()
	if requireEpoch && (!g.known || g.blocked || g.epoch != expected) {
		g.mu.Unlock()
		<-g.transition
		return nil, ErrStaleEpoch
	}
	g.blocked = true
	g.known = false
	g.hasPeer = false
	g.identity = [32]byte{}
	g.epoch++
	epoch := g.epoch
	leases := make([]*probeLease, 0, len(g.live))
	for lease := range g.live {
		leases = append(leases, lease)
	}
	g.mu.Unlock()
	for _, lease := range leases {
		lease.cancel()
	}
	for _, lease := range leases {
		select {
		case <-lease.done:
		case <-ctx.Done():
			<-g.transition
			return nil, ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		<-g.transition
		return nil, err
	}
	return &ActiveTransition{guard: g, epoch: epoch}, nil
}

func (transition *ActiveTransition) Commit(actual ActiveState) error {
	if !transition.done.CompareAndSwap(false, true) {
		return ErrClosedTransition
	}
	g := transition.guard
	defer func() { <-g.transition }()
	known, peer, id, err := activeIdentity(actual)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.epoch != transition.epoch || !g.blocked {
		return ErrClosedTransition
	}
	// Invalid/aborted updates never restore a guessed or previous identity.
	g.known = known
	g.hasPeer = peer
	g.identity = id
	g.blocked = false
	return err
}

// Abort leaves the actual identity unknown. It never resumes a stale snapshot.
func (transition *ActiveTransition) Abort() error {
	return transition.Commit(ActiveState{})
}
