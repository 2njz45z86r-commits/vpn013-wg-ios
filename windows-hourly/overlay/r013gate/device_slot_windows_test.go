// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type slotFixtureDevice struct {
	name string
	sets atomic.Uint32
}

func (d *slotFixtureDevice) IpcGetOperation(w io.Writer) error {
	_, e := io.WriteString(w, "fixture="+d.name+"\n")
	return e
}
func (d *slotFixtureDevice) IpcSet(s string) error { d.sets.Add(1); return nil }
func slotValue(s *PrimaryDeviceSlot) (string, error) {
	var w strings.Builder
	e := s.IpcGetOperation(&w)
	return w.String(), e
}

func TestQueuedPrimarySetChoosesDeviceOnlyAfterActualMutationFence(t *testing.T) {
	requireCI(t)
	g := testGate(t, testName(t))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	old, next := &slotFixtureDevice{name: "old"}, &slotFixtureDevice{name: "next"}
	s, e := NewPrimaryDeviceSlot(ctx, g, old)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	e = g.Primary(ctx, Stamp{}, func(context.Context) error {
		before := g.Current()
		go func() { done <- s.IpcSet("complete bounded body") }()
		end := time.Now().Add(time.Second)
		for g.Current() == before {
			if time.Now().After(end) {
				return errors.New("set did not queue on held fence")
			}
			time.Sleep(time.Millisecond)
		}
		// Nested owner mutation replaces the backend while the pending Set is
		// still outside the kernel barrier. A preselected old pointer is wrong.
		return s.Swap(Stamp{}, func(current PrimaryUAPIDevice) (PrimaryUAPIDevice, error) {
			if current != old {
				return nil, ErrUnavailable
			}
			return next, nil
		})
	})
	if e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("queued set did not finish")
	}
	if old.sets.Load() != 0 || next.sets.Load() != 1 {
		t.Fatal("set applied to retired backend")
	}
	before := g.Current()
	if value, e := slotValue(s); e != nil || value != "fixture=next\n" || g.Current() != before {
		t.Fatal("read changed generation or used stale backend")
	}
}

type slotBlockedWriter struct {
	started chan struct{}
	release chan struct{}
}

func (w *slotBlockedWriter) Write(p []byte) (int, error) {
	close(w.started)
	<-w.release
	return len(p), nil
}
func TestPrimarySnapshotReleasesDeviceBeforeBlockedPipeWrite(t *testing.T) {
	requireCI(t)
	g := testGate(t, testName(t))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s, _ := NewPrimaryDeviceSlot(ctx, g, &slotFixtureDevice{name: "old"})
	w := &slotBlockedWriter{started: make(chan struct{}), release: make(chan struct{})}
	defer close(w.release)
	done := make(chan error, 1)
	go func() { done <- s.IpcGetOperation(w) }()
	select {
	case <-w.started:
	case <-ctx.Done():
		t.Fatal("read did not reach pipe writer")
	}
	if e := s.Swap(Stamp{}, func(PrimaryUAPIDevice) (PrimaryUAPIDevice, error) { return &slotFixtureDevice{name: "next"}, nil }); e != nil {
		t.Fatal(e)
	}
	if value, e := slotValue(s); e != nil || value != "fixture=next\n" {
		t.Fatal("blocked reader held backend swap lock")
	}
}

func TestPrimarySlotOneShotRollbackAndCancellationStayExplicit(t *testing.T) {
	requireCI(t)
	for _, scenario := range []string{"stale-choice", "verified-rollback", "cancelled-owner", "typed-nil-replacement"} {
		t.Run(scenario, func(t *testing.T) {
			g := testGate(t, testName(t))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, _ := NewPrimaryDeviceSlot(ctx, g, &slotFixtureDevice{name: "old"})
			stamp := g.Current()
			called := false
			switch scenario {
			case "stale-choice":
				g.NotifyChange()
				e := s.Swap(stamp, func(PrimaryUAPIDevice) (PrimaryUAPIDevice, error) { called = true; return nil, nil })
				if !errors.Is(e, ErrStale) || called {
					t.Fatal("stale conditional transition ran")
				}
			case "verified-rollback":
				failure := errors.New("synthetic apply failed")
				e := s.Swap(Stamp{}, func(PrimaryUAPIDevice) (PrimaryUAPIDevice, error) {
					return &slotFixtureDevice{name: "rolled-back"}, failure
				})
				if !errors.Is(e, failure) {
					t.Fatal("failure hidden by rollback")
				}
				if value, e := slotValue(s); e != nil || value != "fixture=rolled-back\n" {
					t.Fatal("verified rollback was not actual current backend")
				}
			case "cancelled-owner":
				cancel()
				e := s.Swap(stamp, func(PrimaryUAPIDevice) (PrimaryUAPIDevice, error) { called = true; return nil, nil })
				if e == nil || called || g.Current() != stamp {
					t.Fatal("cancelled owner mutated primary")
				}
			case "typed-nil-replacement":
				var absent *slotFixtureDevice
				if _, e := NewPrimaryDeviceSlot(ctx, g, absent); e == nil {
					t.Fatal("typed nil initial backend accepted")
				}
				e := s.Swap(Stamp{}, func(PrimaryUAPIDevice) (PrimaryUAPIDevice, error) { return absent, nil })
				if e == nil {
					t.Fatal("missing backend reported as successful switch")
				}
				if _, e = slotValue(s); e == nil {
					t.Fatal("missing backend fell back to old seed")
				}
			}
		})
	}
}
