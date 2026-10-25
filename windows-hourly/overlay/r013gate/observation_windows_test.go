// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestObservedPathRevisionNeverCommitsFailureOrStaleNotification(t *testing.T) {
	requireCI(t)
	var state PathObservationState
	if _, ready := state.Snapshot(); ready {
		t.Fatal("unobserved path reported ready")
	}
	first := state.Changed()
	state.Commit(first, 7, nil)
	if index, ready := state.Snapshot(); !ready || index != 7 {
		t.Fatal("successful actual path not committed")
	}
	old := state.Revision()
	state.Changed()
	state.Commit(old, 8, nil)
	if _, ready := state.Snapshot(); ready {
		t.Fatal("notification during work disappeared")
	}
	state.Commit(state.Revision(), 9, errors.New("native bind failed"))
	if index, ready := state.Snapshot(); ready || index != 0 {
		t.Fatal("failed bind leaked a guessed index")
	}
	state.Commit(state.Revision(), 0, nil)
	if index, ready := state.Snapshot(); !ready || index != 0 {
		t.Fatal("primary reset must remain zero for probe denial")
	}
}
func TestObservedMetadataRequiresLiveConcreteLeaseAndCarriesNoPrivateConfig(t *testing.T) {
	requireCI(t)
	gate := testGate(t, testName(t))
	err := gate.Candidate(context.Background(), func(_ context.Context, token Token) error {
		valid := Observation{Version: ObservationVersion, PID: 123, Name: "fixture", Stamp: token.Stamp(), Ready: true, TunnelIndex: 7, Physical4: 8, Identity: strings.Repeat("a", 64)}
		if valid.Validate(token, "fixture", 123) != nil {
			return errors.New("fresh metadata refused")
		}
		for _, change := range []func(*Observation){func(o *Observation) { o.Stamp.Epoch++ }, func(o *Observation) { o.PID++ }, func(o *Observation) { o.Ready = false }, func(o *Observation) { o.Dirty = true }, func(o *Observation) { o.Scripts = true }, func(o *Observation) { o.Physical4 = 0 }, func(o *Observation) { o.Physical6 = o.TunnelIndex }, func(o *Observation) { o.TunnelIndex = 0 }, func(o *Observation) { o.Identity = "unknown" }} {
			altered := valid
			change(&altered)
			if altered.Validate(token, "fixture", 123) == nil {
				return errors.New("unconfirmed metadata accepted")
			}
		}
		bytes, _ := json.Marshal(valid)
		if strings.Contains(string(bytes), "private") || strings.Contains(string(bytes), "configuration") {
			return errors.New("private config exposed in observation")
		}
		if valid.Validate(Token{}, "fixture", 123) == nil {
			return errors.New("zero lease accepted")
		}
		gate.NotifyChange()
		if valid.Validate(token, "fixture", 123) == nil {
			return errors.New("stale observed metadata accepted")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
