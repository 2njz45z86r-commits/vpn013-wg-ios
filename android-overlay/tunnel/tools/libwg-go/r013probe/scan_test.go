// SPDX-License-Identifier: MIT
package awgprobe

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func scanCandidateForTest(t *testing.T, id string, guard *ActiveGuard, delay time.Duration) ScanCandidate {
	t.Helper()
	r, peer := fixture(t)
	r.Guard = guard
	peer.dns.Store(true)
	peer.delay.Store(int64(delay))
	var endpoint netip.AddrPort
	for _, line := range strings.Split(r.Config, "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			endpoint = netip.MustParseAddrPort(strings.TrimPrefix(line, "endpoint="))
		}
	}
	r.Bind, _ = NewPhysicalBind(endpoint, loopbackPhysicalFactory{})
	return ScanCandidate{ID: id, DNSRequest: DNSRequest{Request: r, Port: 53}}
}

func TestScanSelectsBetterDNSAndRechecksFreshProfileBeforeSwitch(t *testing.T) {
	active, _ := fixture(t)
	guard := guardForTest(t, ActiveState{Known: true, Configuration: active.Config})
	slow := scanCandidateForTest(t, "slow", guard, 20*time.Millisecond)
	fast := scanCandidateForTest(t, "fast", guard, time.Millisecond)
	duplicate := fast
	duplicate.ID = "renamed_alias"
	f := &fakeTunnelFactory{delay: 40 * time.Millisecond}
	out, err := Scan(context.Background(), ScanRequest{AutoActive: true, Current: CurrentDNSRequest{Target: netip.AddrPortFrom(fast.Target, 53), Factory: f, Guard: guard}, Candidates: []ScanCandidate{slow, fast, duplicate}})
	if err != nil || out.Choice == nil || out.Choice.ID != "fast" || len(out.Measurements) != 3 || out.Measurements[2].Status != "duplicate_snapshot_skipped" || out.NextIndex != 0 {
		t.Fatal("wrong selection", out, err)
	}
	if f.writes.Load() != 8 || f.opens.Load() != 2 || f.closed.Load() != 2 {
		t.Fatal("fresh before/after baselines missing")
	}
	changed := fast
	changed.Config += "persistent_keepalive_interval=15\n"
	if _, err := out.Choice.BeginSwitch(context.Background(), changed); !errors.Is(err, ErrCandidateChanged) {
		t.Fatal("edited profile accepted", err)
	}
	changed = fast
	changed.Source = netip.MustParseAddr("10.13.99.3")
	if _, err := out.Choice.BeginSwitch(context.Background(), changed); !errors.Is(err, ErrCandidateChanged) {
		t.Fatal("edited source address accepted", err)
	}
	tr, err := out.Choice.BeginSwitch(context.Background(), fast)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Commit(ActiveState{Known: true, Configuration: fast.Config}) != nil {
		t.Fatal("cannot commit actual applied state")
	}
	if _, err := out.Choice.BeginSwitch(context.Background(), fast); !errors.Is(err, ErrStaleEpoch) {
		t.Fatal("old choice replayed", err)
	}
}

func TestScanPreservesDifferentSettingsOfInactiveIdentity(t *testing.T) {
	active, _ := fixture(t)
	guard := guardForTest(t, ActiveState{Known: true, Configuration: active.Config})
	first := scanCandidateForTest(t, "first", guard, time.Millisecond)
	alternate := first
	alternate.ID = "alternate"
	alternate.Config = strings.Replace(first.Config, "jc=3\n", "jc=4\n", 1)
	var endpoint netip.AddrPort
	for _, line := range strings.Split(first.Config, "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			endpoint = netip.MustParseAddrPort(strings.TrimPrefix(line, "endpoint="))
		}
	}
	alternate.Bind, _ = NewPhysicalBind(endpoint, loopbackPhysicalFactory{})
	f := &fakeTunnelFactory{delay: 20 * time.Millisecond}
	out, err := Scan(context.Background(), ScanRequest{AutoActive: true, Current: CurrentDNSRequest{Target: netip.AddrPortFrom(first.Target, 53), Factory: f, Guard: guard}, Candidates: []ScanCandidate{first, alternate}})
	if err != nil || len(out.Measurements) != 2 || out.Measurements[0].Status != "measured" || out.Measurements[1].Status != "measured" {
		t.Fatal("inactive alternate settings discarded", out, err)
	}
}

func TestScanNeverMeasuresManualModeOrInvalidCandidateSets(t *testing.T) {
	r, _ := fixture(t)
	guard := guardForTest(t, ActiveState{Known: true, Configuration: r.Config})
	f := &fakeTunnelFactory{}
	c := ScanCandidate{ID: "one", DNSRequest: DNSRequest{Request: r, Port: 53}}
	c.Guard = guard
	base := ScanRequest{Current: CurrentDNSRequest{Target: netip.AddrPortFrom(r.Target, 53), Factory: f, Guard: guard}, Candidates: []ScanCandidate{c}}
	if _, err := Scan(context.Background(), base); !errors.Is(err, ErrAutoInactive) {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ScanRequest){
		"none":               func(x *ScanRequest) { x.Candidates = nil },
		"over30":             func(x *ScanRequest) { x.Candidates = make([]ScanCandidate, 31) },
		"repeated_id":        func(x *ScanRequest) { x.Candidates = []ScanCandidate{c, c} },
		"foreign_guard":      func(x *ScanRequest) { x.Candidates[0].Guard = guardForTest(t, ActiveState{Known: true}) },
		"different_resolver": func(x *ScanRequest) { x.Candidates[0].Port = 54 },
	} {
		t.Run(name, func(t *testing.T) {
			x := base
			x.AutoActive = true
			x.Candidates = append([]ScanCandidate(nil), base.Candidates...)
			change(&x)
			if _, err := Scan(context.Background(), x); !errors.Is(err, ErrInvalidScan) {
				t.Fatal(err)
			}
		})
	}
	if f.opens.Load() != 0 {
		t.Fatal("manual/invalid scan opened a transport")
	}
}

func TestScanDoesNotSelectWhenCurrentDNSIsFaster(t *testing.T) {
	active, _ := fixture(t)
	guard := guardForTest(t, ActiveState{Known: true, Configuration: active.Config})
	c := scanCandidateForTest(t, "slower", guard, 20*time.Millisecond)
	f := &fakeTunnelFactory{delay: time.Millisecond}
	out, err := Scan(context.Background(), ScanRequest{AutoActive: true, Current: CurrentDNSRequest{Target: netip.AddrPortFrom(c.Target, 53), Factory: f, Guard: guard}, Candidates: []ScanCandidate{c}})
	if err != nil || out.Choice != nil || len(out.Measurements) != 1 || out.Measurements[0].Status != "measured" {
		t.Fatal("unnecessary switch chosen", out, err)
	}
}
