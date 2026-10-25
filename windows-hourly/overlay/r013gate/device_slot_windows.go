// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"io"
	"reflect"
	"strings"
	"sync"
)

// PrimaryDeviceSlot chooses the actual device AFTER acquiring the mutation
// barrier. Keeping a pointer chosen before a queued swap could configure an
// already retired engine. Reads do not invalidate generation; a private bounded
// snapshot is copied before any potentially blocking pipe write.
type PrimaryDeviceSlot struct {
	ctx     context.Context
	gate    *Gate
	mu      sync.RWMutex
	current PrimaryUAPIDevice
}

func availablePrimaryDevice(value PrimaryUAPIDevice) bool {
	if value == nil {
		return false
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return !v.IsNil()
	}
	return true
}

func NewPrimaryDeviceSlot(ctx context.Context, gate *Gate, initial PrimaryUAPIDevice) (*PrimaryDeviceSlot, error) {
	if ctx == nil || ctx.Err() != nil || gate == nil || !availablePrimaryDevice(initial) {
		return nil, ErrUnavailable
	}
	return &PrimaryDeviceSlot{ctx: ctx, gate: gate, current: initial}, nil
}

func (s *PrimaryDeviceSlot) IpcGetOperation(writer io.Writer) error {
	if writer == nil || s.ctx.Err() != nil {
		return ErrUnavailable
	}
	s.mu.RLock()
	if s.current == nil {
		s.mu.RUnlock()
		return ErrUnavailable
	}
	var private strings.Builder
	err := s.current.IpcGetOperation(&cappedUAPIWriter{writer: &private, remaining: maxUAPIBytes})
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	_, err = io.WriteString(writer, private.String())
	return err
}

func (s *PrimaryDeviceSlot) IpcSet(body string) error {
	if len(body) > maxUAPIBytes || s.ctx.Err() != nil {
		return ErrUnavailable
	}
	return s.gate.Primary(s.ctx, Stamp{}, func(context.Context) error {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.current == nil || s.ctx.Err() != nil {
			return ErrUnavailable
		}
		return s.current.IpcSet(body)
	})
}

// Swap serializes actual backend retirement/replacement under the one-shot
// expected Stamp. A failed transition may return a verified rollback engine;
// that engine becomes current while the original failure is returned. A nil
// replacement leaves the slot unavailable, never a guessed preceding seed.
// The owner must invoke this in its service main loop and update select/OS
// configuration there. This primitive alone performs no route or profile work.
func (s *PrimaryDeviceSlot) Swap(expected Stamp, transition func(PrimaryUAPIDevice) (PrimaryUAPIDevice, error)) error {
	if transition == nil || s.ctx.Err() != nil {
		return ErrUnavailable
	}
	return s.gate.Primary(s.ctx, expected, func(context.Context) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.current == nil || s.ctx.Err() != nil {
			return ErrUnavailable
		}
		next, err := transition(s.current)
		if !availablePrimaryDevice(next) {
			next = nil
		}
		s.current = next
		if err == nil && s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		if next == nil && err == nil {
			return ErrUnavailable
		}
		return err
	})
}

func (s *PrimaryDeviceSlot) Observe(read func(PrimaryUAPIDevice) (Observation, error)) (Observation, error) {
	if read == nil || s.ctx.Err() != nil {
		return Observation{}, ErrUnavailable
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil || s.ctx.Err() != nil {
		return Observation{}, ErrUnavailable
	}
	return read(s.current)
}

var _ PrimaryUAPIDevice = (*PrimaryDeviceSlot)(nil)
