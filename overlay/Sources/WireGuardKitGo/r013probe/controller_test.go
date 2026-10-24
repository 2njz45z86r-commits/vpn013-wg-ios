// SPDX-License-Identifier: MIT
package awgprobe

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func controllerForTest(t *testing.T, current *fakeTunnelFactory) (*Controller, Snapshot, ScanInput) {
	t.Helper()
	active, _ := fixture(t)
	c, err := NewController(loopbackPhysicalFactory{}, current)
	if err != nil {
		t.Fatal(err)
	}
	change, err := c.BeginChange(context.Background())
	if err != nil || c.CommitChange(change, ActiveState{Known: true, Configuration: active.Config}) != nil {
		t.Fatal("initial actual identity", err)
	}
	candidate := scanCandidateForTest(t, "opaque-candidate-id", c.guard, time.Millisecond)
	snapshot := Snapshot{candidate.ID, candidate.Config, candidate.Source.String()}
	in := ScanInput{AutoActive: true, Resolver: netip.AddrPortFrom(candidate.Target, candidate.Port).String(), Candidates: []Snapshot{snapshot}}
	t.Cleanup(func() {
		if err := c.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return c, snapshot, in
}

func awaitController(t *testing.T, c *Controller, operation uint64) ScanStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s, err := c.PollScan(operation)
		if err != nil {
			t.Fatal(err)
		}
		if s.Status != "pending" {
			return s
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("controller did not complete")
	return ScanStatus{}
}

func TestControllerMeasuresThenAppliesOnlyFreshOneShotChoice(t *testing.T) {
	c, snapshot, in := controllerForTest(t, &fakeTunnelFactory{delay: 20 * time.Millisecond})
	op, err := c.StartScan(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.StartScan(in); !errors.Is(err, ErrControllerBusy) {
		t.Fatal("unbounded concurrent operations", err)
	}
	out := awaitController(t, c, op)
	if out.Status != "complete" || out.ChoiceID != snapshot.ID || len(out.Rows) != 1 || out.Rows[0].Status != "measured" {
		t.Fatal(out)
	}
	wire, _ := json.Marshal(out)
	if strings.Contains(string(wire), "private_key") || strings.Contains(string(wire), snapshot.Config) {
		t.Fatal("configuration leaked in results")
	}
	// Exported result values cannot mutate the retained operation.
	out.Before.Epoch = 0
	out.Rows[0].ID = "edited"
	retained, _ := c.PollScan(op)
	if retained.Before.Epoch == 0 || retained.Rows[0].ID != snapshot.ID {
		t.Fatal("result aliases retained state")
	}
	change, err := c.BeginChoice(context.Background(), op, snapshot, in.Resolver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.BeginChange(context.Background()); !errors.Is(err, ErrControllerBusy) {
		t.Fatal("overlapping primary changes", err)
	}
	if err := c.CommitChange(change+1, ActiveState{Known: true}); !errors.Is(err, ErrInvalidHandle) {
		t.Fatal("foreign transition accepted")
	}
	if err := c.CommitChange(change, ActiveState{Known: true, Configuration: snapshot.Config}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.BeginChoice(context.Background(), op, snapshot, in.Resolver); !errors.Is(err, ErrInvalidHandle) {
		t.Fatal("choice replayed", err)
	}
	if s, _ := c.PollScan(op); s.Status != "stale" {
		t.Fatal("old measurements displayed", s)
	}
}

func TestControllerChangeWaitsForRealCloseAndTimeoutDoesNotAuthorizeMutation(t *testing.T) {
	closed := make(chan func(), 1)
	f := &fakeTunnelFactory{silent: true, cancelled: closed}
	c, _, in := controllerForTest(t, f)
	op, err := c.StartScan(in)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for f.opens.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	change, err := c.BeginChange(ctx)
	if change != 0 || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("close not acknowledged but primary mutation granted", change, err)
	}
	var ack func()
	select {
	case ack = <-closed:
	case <-time.After(time.Second):
		t.Fatal("cancel did not reach current session")
	}
	if _, err := c.PollScan(op); err != nil {
		t.Fatal("timed-out controller lost ownership", err)
	}
	ack()
	awaitController(t, c, op)
	// A new explicit transition recovers from UNKNOWN only after the drain.
	change, err = c.BeginChange(context.Background())
	if err != nil || c.CommitChange(change, ActiveState{Known: true}) != nil {
		t.Fatal(err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.StartScan(in); !errors.Is(err, ErrControllerClosed) {
		t.Fatal("closed controller reused", err)
	}
}

func TestControllerEditedAndCancelledResultsNeverSwitch(t *testing.T) {
	for _, action := range []string{"edit", "cancel", "change"} {
		t.Run(action, func(t *testing.T) {
			c, snapshot, in := controllerForTest(t, &fakeTunnelFactory{delay: 15 * time.Millisecond})
			op, err := c.StartScan(in)
			if err != nil {
				t.Fatal(err)
			}
			if awaitController(t, c, op).ChoiceID == "" {
				t.Fatal("fixture did not select a candidate")
			}
			switch action {
			case "edit":
				snapshot.Config += "persistent_keepalive_interval=25\n"
			case "cancel":
				if err := c.CancelScan(context.Background(), op); err != nil {
					t.Fatal(err)
				}
			case "change":
				tr, err := c.BeginChange(context.Background())
				if err != nil || c.CommitChange(tr, ActiveState{Known: true}) != nil {
					t.Fatal(err)
				}
			}
			if tr, err := c.BeginChoice(context.Background(), op, snapshot, in.Resolver); err == nil || tr != 0 {
				t.Fatal("stale or cancelled choice accepted")
			}
		})
	}
}

func TestControllerInputBoundsAndUnknownMembershipFailClosed(t *testing.T) {
	f := &fakeTunnelFactory{}
	c, _ := NewController(loopbackPhysicalFactory{}, f)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	r, _ := fixture(t)
	snapshot := Snapshot{"one", r.Config, r.Source.String()}
	in := ScanInput{AutoActive: true, Resolver: "1.1.1.1:53", Candidates: []Snapshot{snapshot}}
	op, err := c.StartScan(in)
	if err != nil {
		t.Fatal(err)
	}
	if awaitController(t, c, op).Status != "unavailable" || f.opens.Load() != 0 {
		t.Fatal("unknown state opened UDP")
	}
	valid, _ := json.Marshal(in)
	if _, err := DecodeScanInput(valid); err != nil {
		t.Fatal(err)
	}
	for name, wire := range map[string][]byte{
		"empty": nil, "over4MiB": make([]byte, MaxScanJSON+1), "unknown": []byte(`{"extra":true}`), "trailing": append(valid, []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeScanInput(wire); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
	for name, change := range map[string]func(*ScanInput){
		"manual":              func(s *ScanInput) { s.AutoActive = false },
		"over30":              func(s *ScanInput) { s.Candidates = make([]Snapshot, 31) },
		"oversize_config":     func(s *ScanInput) { s.Candidates[0].Config = strings.Repeat("x", 65537) },
		"unresolved_endpoint": func(s *ScanInput) { s.Candidates[0].Config += "endpoint=example.invalid:53\n" },
		"duplicate_id":        func(s *ScanInput) { s.Candidates = append(s.Candidates, s.Candidates[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			s := in
			s.Candidates = append([]Snapshot(nil), in.Candidates...)
			change(&s)
			if _, err := c.StartScan(s); err == nil {
				t.Fatal("invalid scan accepted")
			}
		})
	}
	if f.opens.Load() != 0 {
		t.Fatal("invalid scan opened UDP")
	}
}

func TestTransferredChoiceCannotBeCommittedThroughItsOldControllerToken(t *testing.T) {
	c, _, in := controllerForTest(t, &fakeTunnelFactory{})
	id, err := c.BeginChange(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	finish, err := c.TransferChange(id)
	if err != nil {
		t.Fatal(err)
	}
	if c.CommitChange(id, ActiveState{Known: true}) != ErrInvalidHandle {
		t.Fatal("transferred token still usable")
	}
	if _, err := c.StartScan(in); err != ErrControllerBusy {
		t.Fatal("scan opened during adopted primary mutation", err)
	}
	if err := finish(ActiveState{Known: true}); err != nil {
		t.Fatal(err)
	}
	if err := finish(ActiveState{Known: true}); err != ErrClosedTransition {
		t.Fatal("transferred permit replayed", err)
	}
}

func TestSharedPrimaryGuardDrainsPredecessorControllerBeforeSuccessorChanges(t *testing.T) {
	guard, _ := NewActiveGuard(ActiveState{})
	ack := make(chan func(), 1)
	f := &fakeTunnelFactory{silent: true, cancelled: ack}
	old, _ := NewControllerWithGuard(loopbackPhysicalFactory{}, f, guard)
	newer, _ := NewControllerWithGuard(loopbackPhysicalFactory{}, &fakeTunnelFactory{}, guard)
	active, _ := fixture(t)
	id, err := old.BeginChange(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if old.CommitChange(id, ActiveState{Known: true, Configuration: active.Config}) != nil {
		t.Fatal("initial membership")
	}
	candidate := scanCandidateForTest(t, "other", guard, time.Millisecond)
	op, err := old.StartScan(ScanInput{AutoActive: true, Resolver: netip.AddrPortFrom(candidate.Target, 53).String(), Candidates: []Snapshot{{candidate.ID, candidate.Config, candidate.Source.String()}}})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for f.opens.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	changed := make(chan uint64, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		id, _ := newer.BeginChange(ctx)
		changed <- id
	}()
	var closeAck func()
	select {
	case closeAck = <-ack:
	case <-time.After(time.Second):
		t.Fatal("predecessor session was not cancelled")
	}
	select {
	case id := <-changed:
		closeAck()
		t.Fatal("successor changed before real close", id)
	default:
	}
	closeAck()
	id = <-changed
	if id == 0 || newer.CommitChange(id, ActiveState{Known: true}) != nil {
		t.Fatal("successor did not receive a real drained permit")
	}
	if awaitController(t, old, op).Status == "complete" {
		t.Fatal("predecessor result survived successor epoch")
	}
	if old.Close(context.Background()) != nil || newer.Close(context.Background()) != nil {
		t.Fatal("controllers did not release")
	}
}
