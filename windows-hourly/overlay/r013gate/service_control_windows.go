// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows/svc"
)

// ServiceControl receives SCM requests independently of a busy owner main loop.
// Stop invalidates generation before the next queued conditional mutation can
// begin. Only one coalesced nonterminal request is retained. onStop must be the
// owner's bounded atomic/context invalidation, never subprocess/IPC or drain.
type ServiceControl struct {
	cancel   context.CancelFunc
	done     chan struct{}
	stop     chan struct{}
	requests chan svc.ChangeRequest
	stopped  atomic.Bool
	stopOnce sync.Once
}

func NewServiceControl(parent context.Context, gate *Gate, input <-chan svc.ChangeRequest, onStop func()) (*ServiceControl, error) {
	if parent == nil || parent.Err() != nil || gate == nil || input == nil || onStop == nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	s := &ServiceControl{cancel: cancel, done: make(chan struct{}), stop: make(chan struct{}), requests: make(chan svc.ChangeRequest, 1)}
	terminal := func() { s.stopOnce.Do(func() { s.stopped.Store(true); gate.NotifyChange(); onStop(); close(s.stop) }) }
	go func() {
		defer close(s.done)
		defer close(s.requests)
		for {
			select {
			case <-ctx.Done():
				return
			case request, ok := <-input:
				if !ok || request.Cmd == svc.Stop || request.Cmd == svc.Shutdown {
					terminal()
					return
				}
				select {
				case s.requests <- request:
				default:
					select {
					case <-s.requests:
					default:
					}
					select {
					case s.requests <- request:
					default:
					}
				}
			}
		}
	}()
	return s, nil
}
func (s *ServiceControl) Requests() <-chan svc.ChangeRequest { return s.requests }
func (s *ServiceControl) StopRequested() <-chan struct{}     { return s.stop }
func (s *ServiceControl) Stopped() bool                      { return s.stopped.Load() }
func (s *ServiceControl) Close(ctx context.Context) error {
	if ctx == nil {
		return ErrUnavailable
	}
	s.cancel()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
