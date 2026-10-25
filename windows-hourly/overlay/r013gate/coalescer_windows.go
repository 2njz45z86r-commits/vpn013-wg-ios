// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Coalescer owns exactly one cancellable path worker and one pending burst.
// OS callbacks only invalidate and enqueue; they never wait for Primary. Close
// cancels queued kernel waits and drains the worker before returning, including
// when its caller already owns the primary barrier during watcher replacement.
type Coalescer struct {
	mu             sync.Mutex
	gate           *Gate
	ctx            context.Context
	cancel         context.CancelFunc
	wake           chan struct{}
	done           chan struct{}
	closed         bool
	first, last    time.Time
	delay, maximum time.Duration
	work           func() error
}

func NewCoalescer(parent context.Context, gate *Gate, delay, maximum time.Duration, work func() error) (*Coalescer, error) {
	if parent == nil || parent.Err() != nil || gate == nil || delay <= 0 || maximum < delay || maximum > 5*time.Second || work == nil {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(parent)
	c := &Coalescer{gate: gate, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{}), delay: delay, maximum: maximum, work: work}
	go c.run()
	return c, nil
}
func (c *Coalescer) Notify() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.ctx.Err() != nil {
		return
	}
	c.gate.NotifyChange()
	now := time.Now()
	if c.first.IsZero() {
		c.first = now
	}
	c.last = now
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *Coalescer) deadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.first.IsZero() {
		return time.Time{}, false
	}
	end := c.last.Add(c.delay)
	maximum := c.first.Add(c.maximum)
	if maximum.Before(end) {
		end = maximum
	}
	return end, true
}
func (c *Coalescer) consume() {
	c.mu.Lock()
	c.first = time.Time{}
	c.last = time.Time{}
	c.mu.Unlock()
}
func (c *Coalescer) run() {
	defer close(c.done)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	var tick <-chan time.Time
	reset := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		if end, ok := c.deadline(); ok {
			delay := time.Until(end)
			if delay < 0 {
				delay = 0
			}
			timer.Reset(delay)
			tick = timer.C
		} else {
			tick = nil
		}
	}
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.wake:
			reset()
		case <-tick:
			// A newer notification may have moved the trailing deadline while the timer
			// was becoming ready. Recheck rather than executing a stale early callback.
			if end, ok := c.deadline(); ok && time.Until(end) > 0 {
				reset()
				continue
			}
			c.consume()
			tick = nil
			_ = c.gate.Primary(c.ctx, Stamp{}, func(context.Context) error { return c.work() })
			reset()
		}
	}
}
func (c *Coalescer) Close(ctx context.Context) error {
	if ctx == nil {
		return errors.New("close context required")
	}
	c.mu.Lock()
	c.closed = true
	c.cancel()
	c.mu.Unlock()
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
