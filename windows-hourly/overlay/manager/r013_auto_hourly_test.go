// SPDX-License-Identifier: MIT
package manager

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013prepare"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
)

func TestAutoStartPreservesRunningAndNeverInventsUnknownSeed(t *testing.T) {
	oldState, oldStart, oldSupervise, oldValidate := stateR013Tunnel, startR013Tunnel, superviseR013Auto, validateStoppedR013Auto
	oldRun := autoRun
	autoRun = nil
	defer func() {
		stateR013Tunnel = oldState
		startR013Tunnel = oldStart
		superviseR013Auto = oldSupervise
		validateStoppedR013Auto = oldValidate
		autoRun = oldRun
	}()
	for _, tc := range []struct {
		name                              string
		state                             TunnelState
		queryError, seedError             error
		starts, validations, supervisions int
		failure                           bool
	}{
		{name: "running-preserved", state: TunnelStarted, supervisions: 1},
		{name: "starting-preserved", state: TunnelStarting, supervisions: 1},
		{name: "unknown-untouched", state: TunnelUnknown, failure: true},
		{name: "SCM-error-untouched", queryError: errors.New("denied"), failure: true},
		{name: "stopped-no-matching-seed", state: TunnelStopped, seedError: r013vault.ErrVault, validations: 1, failure: true},
		{name: "stopped-exact-working-only", state: TunnelStopped, validations: 1, starts: 1, supervisions: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			starts, validations, supervisions := 0, 0, 0
			stateR013Tunnel = func(*ManagerService, string) (TunnelState, error) { return tc.state, tc.queryError }
			startR013Tunnel = func(_ *ManagerService, name string) error {
				if name != r013.AutoName {
					t.Fatal("wrong service")
				}
				starts++
				return nil
			}
			superviseR013Auto = func(*ManagerService) { supervisions++ }
			validateStoppedR013Auto = func() error { validations++; return tc.seedError }
			err := (&ManagerService{}).Start(r013.AutoName)
			if (err != nil) != tc.failure || starts != tc.starts || validations != tc.validations || supervisions != tc.supervisions {
				t.Fatal("unexpected destructive action or seed fallback", err, starts, validations, supervisions)
			}
		})
	}
	// A completed observer does not block a later explicit edit; Stop can wait
	// under autoControl because the observer never tries to acquire that mutex.
	_, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	close(done)
	autoRun = &autoSession{cancel: cancel, done: done}
	pruneAutoSession()
	if autoRun != nil {
		t.Fatal("finished supervision retained")
	}
}
func TestAutoSupervisionAcceptsOnlyFullConfirmedVaultMember(t *testing.T) {
	first, err := conf.FromWgQuick("[Interface]\nPrivateKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.213.88.2/32\nDNS = 10.213.99.1\n[Peer]\nPublicKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n", "one")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := r013vault.CopyConfig(*first)
	second.Name = "two"
	second.Peers[0].Endpoint.Host = "192.0.2.2"
	second.Interface.MTU = 1390
	plain, _ := json.Marshal([]conf.Config{*first, second})
	cipher, err := dpapi.Encrypt(plain, "VPN013-Auto-v1")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := r013vault.Decode(cipher)
	if err != nil {
		t.Fatal(err)
	}
	member, digest, err := snapshot.Member(1)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := r013prepare.Identity(member)
	if err != nil {
		t.Fatal(err)
	}
	known := r013gate.ConfirmedMember{Generation: 2, Index: 1, Count: 2, Revision: snapshot.Revision(), Digest: digest}
	observation := r013gate.Observation{Version: r013gate.ObservationVersion, Ready: true, HealthOwned: true, Identity: identity, Member: &known}
	actual := r013gate.PrimarySnapshot{Observation: observation}
	accepted, err := confirmedAutoMember(actual, snapshot)
	if err != nil || accepted.Index != 1 || accepted.Generation != 2 {
		t.Fatal("confirmed winner lost", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*r013gate.Observation)
	}{
		{"old-protocol", func(o *r013gate.Observation) { o.Version = 1 }},
		{"no-health-owner", func(o *r013gate.Observation) { o.HealthOwned = false }},
		{"unknown", func(o *r013gate.Observation) { o.Member = nil }},
		{"stale-generation", func(o *r013gate.Observation) { o.Member.Generation = 0 }},
		{"same-key-different-settings", func(o *r013gate.Observation) { o.Member.Index = 0 }},
		{"changed-revision", func(o *r013gate.Observation) { o.Member.Revision = identity }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := observation
			state := known
			copy.Member = &state
			tc.change(&copy)
			if _, e := confirmedAutoMember(r013gate.PrimarySnapshot{Observation: copy}, snapshot); e == nil {
				t.Fatal("unknown state became seed/current")
			}
		})
	}
}
