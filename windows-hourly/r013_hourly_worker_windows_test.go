// SPDX-License-Identifier: MIT
// Disposable SYSTEM fixture drives the real compiled Auto service, not a mock
// observer, timer or owner. Generated peers and secure-store files are test-only.
package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013winudp"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"github.com/amnezia-vpn/amneziawg-windows/v3/ringlogger"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type hourlyReceipt struct {
	Success, Selected, Compared, TrafficDuringScan, SameTUN, VaultPreserved bool
	Phase, Error                                                            string
	FirstElapsedMillis                                                      int64
	Replies                                                                 uint32
}

func TestPrivateHealthAuthorizationRequiresFreshExactAction(t *testing.T) {
	guard, err := probe.NewActiveGuard(probe.ActiveState{})
	if err != nil {
		t.Fatal(err)
	}
	current := r013gate.ConfirmedMember{Generation: 1, Index: 0, Count: 2, Revision: fmt.Sprintf("%064x", 1), Digest: fmt.Sprintf("%064x", 2)}
	for _, tc := range []struct {
		name            string
		action          r013.Decision
		failures, index int
		latency, age    time.Duration
		valid           bool
	}{
		{name: "retry-current", action: r013.Retry, failures: 1, index: 0, valid: true},
		{name: "second-failure-next", action: r013.Advance, failures: 2, index: 1, valid: true},
		{name: "slow-next", action: r013.Advance, index: 1, latency: 1201 * time.Millisecond, valid: true},
		{name: "first-failure-cannot-advance", action: r013.Advance, failures: 1, index: 1},
		{name: "retry-cannot-change-member", action: r013.Retry, failures: 1, index: 1},
		{name: "old-proof", action: r013.Retry, failures: 1, index: 0, age: 16 * time.Second},
		{name: "future-proof", action: r013.Retry, failures: 1, index: 0, age: -time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := &comparisonHealthProof{guard: guard, action: tc.action, failures: tc.failures, latency: tc.latency, at: time.Now().Add(-tc.age)}
			if proof.valid(tc.index, current) != tc.valid {
				t.Fatal("unexpected private primary authorization")
			}
		})
	}
	if comparisonRequestFresh(time.Time{}) {
		t.Fatal("missing timestamp authorized")
	}
}

type hourlyFixture struct {
	directory string
	receipt   hourlyReceipt
}

func (f *hourlyFixture) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
		case <-requests:
			cancel()
		}
	}()
	err := f.run(ctx)
	if err != nil {
		f.receipt.Error = err.Error()
	} else {
		f.receipt.Success = true
	}
	raw, _ := json.Marshal(f.receipt)
	if os.WriteFile(filepath.Join(f.directory, "hourly-receipt.json"), raw, 0600) != nil {
		return true, 51
	}
	changes <- svc.Status{State: svc.StopPending}
	if err != nil {
		return true, 52
	}
	return false, 0
}

// This is the independent APPLICATION traffic stream, not a candidate factory.
// It is explicitly pinned to the observed TUN and does not hold the comparison
// gate while Auto measures a candidate. Production candidate factories still
// require a concrete live kernel token.
type hourlyApplicationSocket struct{ index uint32 }

func (g hourlyApplicationSocket) PrepareNetwork(role int, network string, fd uintptr) error {
	if role != protectedudp.ThroughTunnel || network != "udp4" || g.index == 0 {
		return r013winudp.ErrBind
	}
	return r013winudp.Pin(fd, windows.AF_INET, g.index)
}
func (f *hourlyFixture) run(ctx context.Context) error {
	f.receipt.Phase = "real-store-and-peers"
	clientBytes, err := os.ReadFile(filepath.Join(f.directory, "client-path.txt"))
	if err != nil {
		return err
	}
	client := string(clientBytes)
	if !filepath.IsAbs(client) {
		return errors.New("compiled client path required")
	}
	_, physical, err := observeCIPhysical()
	if err != nil {
		return err
	}
	first, err := newNativePeer(physical, netip.MustParseAddr("10.213.90.2"), 40*time.Millisecond)
	if err != nil {
		return err
	}
	defer first.device.Close()
	second, err := newNativePeer(physical, netip.MustParseAddr("10.213.91.2"), time.Millisecond)
	if err != nil {
		return err
	}
	defer second.device.Close()
	one, err := fixtureBackendConfig(first, "hourly-one", 1, 1370)
	if err != nil {
		return err
	}
	two, err := fixtureBackendConfig(second, "hourly-two", 1, 1390)
	if err != nil {
		return err
	}
	root, err := conf.RootDirectory(true)
	if err != nil {
		return err
	}
	vaultPath := filepath.Join(root, "r013-auto.dat")
	seed := *one
	seed.Name = r013.AutoName
	seedPath, err := seed.Path()
	if err != nil {
		return err
	}
	for _, path := range []string{vaultPath, seedPath} {
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			return errors.New("fixture refuses existing Auto data")
		}
	}
	raw, _ := json.Marshal([]conf.Config{*one, *two})
	cipher, err := dpapi.Encrypt(raw, "VPN013-Auto-v1")
	if err != nil {
		return err
	}
	vault, err := os.OpenFile(vaultPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(vaultPath)
	if _, err = vault.Write(cipher); err != nil {
		vault.Close()
		return err
	}
	if err = vault.Close(); err != nil {
		return err
	}
	if err = seed.Save(false); err != nil {
		return err
	}
	defer os.Remove(seedPath)
	scm, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer scm.Disconnect()
	service, err := scm.CreateService("VPN013WGTunnel$"+r013.AutoName, client, mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "/tunnelservice", seedPath)
	if err != nil {
		return err
	}
	defer service.Close()
	defer func() {
		service.Control(svc.Stop)
		until := time.Now().Add(12 * time.Second)
		for time.Now().Before(until) {
			state, e := service.Query()
			if e != nil || state.State == svc.Stopped {
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		service.Delete()
	}()
	if err = service.Start(); err != nil {
		return err
	}
	f.receipt.Phase = "actual-compiled-worker-start"
	var initial r013gate.Observation
	until := time.Now().Add(20 * time.Second)
	for time.Now().Before(until) && ctx.Err() == nil {
		value, e := r013gate.ReadObservation(ctx, r013.AutoName)
		if e == nil && value.Ready && value.HealthOwned && value.Member != nil && value.Member.Valid() && value.WorkerStartedUnixNano > 0 {
			initial = value
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if initial.Member == nil || initial.Member.Index != 0 || initial.Member.Generation != 1 {
		status, statusErr := service.Query()
		var logs bytes.Buffer
		logErr := ringlogger.DumpTo(&logs, false)
		var safe []string
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "R013Routing:") || strings.Contains(line, "Startup complete") || strings.Contains(line, "Unable to") || strings.Contains(line, "Firewall error") || strings.Contains(line, "failed") {
				safe = append(safe, line)
			}
		}
		detail := strings.Join(safe, "\n")
		if len(detail) > 10000 {
			detail = detail[len(detail)-10000:]
		}
		return fmt.Errorf("real compiled worker initial exact member unavailable: SCM=%+v query=%v log=%v\n%s", status, statusErr, logErr, detail)
	}
	factory, err := protectedudp.NewForNetwork(protectedudp.ThroughTunnel, hourlyApplicationSocket{initial.TunnelIndex})
	if err != nil {
		return err
	}
	streamCtx, stopStream := context.WithCancel(ctx)
	replies := atomic.Uint32{}
	streamDone := make(chan error, 1)
	go func() {
		streamDone <- nativeStream(streamCtx, factory, netip.MustParseAddrPort("10.213.99.1:53"), &replies)
	}()
	defer func() { stopStream(); <-streamDone; factory.Close(context.Background()) }()
	f.receipt.Phase = "real30s-census-scan-selection"
	// Allow the production30s cadence plus its full unchanged90s scan budget.
	// The earlier65s fixture cutoff canceled a legal in-flight scan.
	until = time.Now().Add(130 * time.Second)
	var scanBefore uint32
	for time.Now().Before(until) && ctx.Err() == nil {
		value, e := r013gate.ReadObservation(ctx, r013.AutoName)
		if e == nil && value.Member != nil {
			elapsed := time.Now().UnixNano() - initial.WorkerStartedUnixNano
			if (value.Comparing || value.LastComparisonUnixNano > 0 || value.Member.Index != 0) && elapsed < int64(29*time.Second) {
				return errors.New("hourly scan ran before actual30s cadence")
			}
			if value.Comparing && value.Member.Generation == 1 {
				if scanBefore == 0 {
					scanBefore = replies.Load()
				} else if replies.Load() > scanBefore {
					f.receipt.TrafficDuringScan = true
				}
			}
			if value.LastComparisonUnixNano > 0 && value.ComparedCount >= 1 {
				f.receipt.Compared = true
			}
			if value.Ready && value.Member.Index == 1 && value.Member.Generation >= 2 {
				f.receipt.Selected = true
				f.receipt.SameTUN = value.TunnelIndex == initial.TunnelIndex
				f.receipt.FirstElapsedMillis = elapsed / int64(time.Millisecond)
				break
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	f.receipt.Replies = replies.Load()
	after, err := os.ReadFile(vaultPath)
	if err != nil {
		return err
	}
	f.receipt.VaultPreserved = string(after) == string(cipher)
	actual, err := conf.LoadFromName(r013.AutoName)
	if err != nil || len(actual.Peers) != 1 || actual.Interface.PrivateKey != two.Interface.PrivateKey || actual.Interface.MTU != two.Interface.MTU {
		var logs bytes.Buffer
		logErr := ringlogger.DumpTo(&logs, false)
		var safe []string
		for _, line := range strings.Split(logs.String(), "\n") {
			if strings.Contains(line, "R013Routing:") {
				safe = append(safe, line)
			}
		}
		detail := strings.Join(safe, "\n")
		if len(detail) > 12000 {
			detail = detail[len(detail)-12000:]
		}
		return fmt.Errorf("selected real working seed not persisted; log=%v\n%s", logErr, detail)
	}
	if !f.receipt.Selected || !f.receipt.Compared || !f.receipt.TrafficDuringScan || !f.receipt.SameTUN || !f.receipt.VaultPreserved || f.receipt.Replies < 2 {
		return errors.New("compiled hourly acceptance incomplete")
	}
	f.receipt.Phase = "done"
	return nil
}
func TestCompiledAutoServiceRunsReal30sScanWithoutStoppingPrimary(t *testing.T) {
	name := fmt.Sprintf("R013HourlyCI-%d", time.Now().UnixNano())
	directory := t.TempDir()
	client := os.Getenv("R013_CI_CLIENT_EXE")
	if !filepath.IsAbs(client) {
		t.Fatal("disposable client missing")
	}
	if err := os.WriteFile(filepath.Join(directory, "client-path.txt"), []byte(client), 0600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	scm, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer scm.Disconnect()
	service, err := scm.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "--r013-hourly-fixture", name, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	defer func() { service.Control(svc.Stop); service.Delete() }()
	if err = service.Start(); err != nil {
		t.Fatal(err)
	}
	var receipt hourlyReceipt
	until := time.Now().Add(190 * time.Second)
	for time.Now().Before(until) {
		if raw, e := os.ReadFile(filepath.Join(directory, "hourly-receipt.json")); e == nil && json.Unmarshal(raw, &receipt) == nil {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !receipt.Success {
		t.Fatalf("actual compiled Auto: %+v", receipt)
	}
	t.Logf("Actual compiled Auto/SYSTEM service: first comparison after %dms, same Wintun selected faster authenticated member, independent primary DNS continued DURING scan (%d replies); original vault unchanged. Disposable local peers, not owner-PC/WAN proof.", receipt.FirstElapsedMillis, receipt.Replies)
}
