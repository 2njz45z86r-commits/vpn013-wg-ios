// SPDX-License-Identifier: MIT
package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013prepare"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"github.com/amnezia-vpn/amneziawg-windows/v3/elevate"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type backendReceipt struct {
	Success                                                             bool
	Phase, Error                                                        string
	Selected, Rollback, Stale, ExternalUnknown, SameTUN, VaultPreserved bool
	Before, After                                                       uint32
}
type backendFixture struct {
	directory string
	receipt   backendReceipt
}

func (f *backendFixture) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-finished:
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
	data, _ := json.Marshal(f.receipt)
	if os.WriteFile(filepath.Join(f.directory, "backend-receipt.json"), data, 0600) != nil {
		return true, 41
	}
	changes <- svc.Status{State: svc.StopPending}
	if err != nil {
		return true, 42
	}
	return false, 0
}
func fixtureBackendConfig(peer nativePeerFixture, name string, dnsLast byte, mtu uint16) (*conf.Config, error) {
	seed := &conf.Config{Name: name, Interface: conf.Interface{Addresses: []conf.IPCidr{{IP: net.ParseIP(peer.source.String()).To4(), Cidr: 32}}, DNS: []net.IP{{10, 213, 99, dnsLast}}, MTU: mtu}}
	c, err := conf.FromUAPI(strings.NewReader(peer.config), seed)
	if err != nil || len(c.Peers) != 1 {
		return nil, errBackendUnknown
	}
	c.Peers[0].AllowedIPs = []conf.IPCidr{{IP: net.IP{0, 0, 0, 0}, Cidr: 0}}
	return c, nil
}
func (f *backendFixture) run(ctx context.Context) error {
	f.receipt.Phase = "identity-and-local-peers"
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	user, err := token.GetTokenUser()
	token.Close()
	if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("not SYSTEM")
	}
	physicalIndex, physical, err := observeCIPhysical()
	if err != nil {
		return err
	}
	first, err := newNativePeer(physical, netip.MustParseAddr("10.213.92.2"), 25*time.Millisecond)
	if err != nil {
		return err
	}
	defer first.device.Close()
	second, err := newNativePeer(physical, netip.MustParseAddr("10.213.93.2"), 8*time.Millisecond)
	if err != nil {
		return err
	}
	defer second.device.Close()
	third, err := newNativePeer(physical, netip.MustParseAddr("10.213.94.2"), time.Millisecond)
	if err != nil {
		return err
	}
	defer third.device.Close()
	one, err := fixtureBackendConfig(first, "one", 1, 1370)
	if err != nil {
		return err
	}
	two, err := fixtureBackendConfig(second, "two", 5, 1390)
	if err != nil {
		return err
	}
	three, err := fixtureBackendConfig(third, "three", 6, 1410)
	if err != nil {
		return err
	}
	rawVault, _ := json.Marshal([]conf.Config{*one, *two, *three})
	cipher, err := dpapi.Encrypt(rawVault, "VPN013-Auto-v1")
	if err != nil {
		return err
	}
	beforeVault := append([]byte(nil), cipher...)
	snapshot, err := r013vault.Decode(cipher)
	if err != nil {
		return err
	}
	gate, err := r013gate.Open()
	if err != nil {
		return err
	}
	defer gate.Close(context.Background())
	if err = firewall.EnableFirewall(0, true, nil); err != nil {
		return err
	}
	defer firewall.DisableFirewall()
	if err = elevate.DropAllPrivileges(true); err != nil {
		return err
	}
	nativeDevice, err := tun.CreateTUN("R013BackendCI", 1370)
	if err != nil {
		return err
	}
	native := nativeDevice.(*tun.NativeTun)
	luid := winipcfg.LUID(native.LUID())
	relay, err := r013tun.New(native)
	if err != nil {
		native.Close()
		return err
	}
	defer relay.Close()
	var engine *device.Device
	var watcher *interfaceWatcher
	defer func() {
		if watcher != nil {
			watcher.Destroy()
		}
		if engine != nil {
			engine.Close()
			<-engine.Wait()
		}
		flushOwnNetwork(luid)
	}()
	working, err := r013vault.CopyConfig(*one)
	if err != nil {
		return err
	}
	working.Name = "R013-Auto"
	configuration := &working
	// Bootstrap the SAME real implementation used by selected and rollback paths.
	var observation comparisonServiceObservation
	owner := &comparisonBackendOwner{ctx: ctx, gate: gate, relay: relay, native: native, configuration: &configuration, engine: &engine, watcher: &watcher, observation: &observation, load: func() (r013vault.Snapshot, error) { return snapshot, nil }, persist: func(*conf.Config) error { return nil }}
	f.receipt.Phase = "restrictive-primary-bootstrap"
	uapi, err := working.ToUAPI()
	if err != nil {
		return err
	}
	if err = gate.Primary(ctx, r013gate.Stamp{}, func(context.Context) error { return owner.install(&working, uapi) }); err != nil {
		return err
	}
	slot, err := r013gate.NewPrimaryDeviceSlot(ctx, gate, engine)
	if err != nil {
		return err
	}
	owner.slot = slot
	owner.confirmInitial()
	observation.ready.Store(true)
	raw, err := engine.IpcGet()
	if err != nil {
		return err
	}
	guard, err := probe.NewActiveGuard(probe.ActiveState{Known: true, Configuration: raw})
	if err != nil {
		return err
	}
	waitStable := func() error {
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			_, aligned := watcher.comparison4.Snapshot()
			if aligned {
				time.Sleep(250 * time.Millisecond)
				_, aligned = watcher.comparison4.Snapshot()
				if aligned {
					return nil
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(25 * time.Millisecond):
			}
		}
		return errors.New("primary binding never settled")
	}
	measure := func(target netip.Addr) error {
		return gate.Candidate(ctx, func(work context.Context, token r013gate.Token) error {
			row, e := luid.Interface()
			if e != nil {
				return e
			}
			factory, e := r013gate.NewUDPFactory(protectedudp.ThroughTunnel, row.InterfaceIndex, 0, token)
			if e != nil {
				return e
			}
			defer factory.Close(context.Background())
			_, e = probe.MeasureCurrentDNS(work, probe.CurrentDNSRequest{Target: netip.AddrPortFrom(target, 53), Factory: factory, Guard: guard})
			return e
		})
	}
	scan := func(index int, currentTarget netip.Addr, stream bool) (*comparisonSelection, error) {
		if err := waitStable(); err != nil {
			return nil, err
		}
		var selection *comparisonSelection
		err := gate.Candidate(ctx, func(work context.Context, token r013gate.Token) error {
			row, e := luid.Interface()
			if e != nil {
				return e
			}
			physicalFactory, e := r013gate.NewUDPFactory(protectedudp.Physical, physicalIndex, 0, token)
			if e != nil {
				return e
			}
			defer physicalFactory.Close(context.Background())
			currentFactory, e := r013gate.NewUDPFactory(protectedudp.ThroughTunnel, row.InterfaceIndex, 0, token)
			if e != nil {
				return e
			}
			defer currentFactory.Close(context.Background())
			raw, e := engine.IpcGet()
			if e != nil {
				return e
			}
			active, e := probe.PublicIdentityDigest(raw)
			if e != nil {
				return e
			}
			original, digest, e := snapshot.Member(index)
			if e != nil {
				return e
			}
			member, e := r013prepare.Prepare(work, original, active, r013prepare.Roles{Physical4: physicalIndex}, net.DefaultResolver)
			if e != nil {
				return e
			}
			physicalBind, e := probe.NewPhysicalBind(member.Endpoint(), physicalFactory)
			if e != nil {
				return e
			}
			fresh := probe.ScanCandidate{ID: fmt.Sprintf("member-%d", index), DNSRequest: probe.DNSRequest{Request: probe.Request{Config: member.UAPI(), Source: member.Source(), Target: currentTarget, Bind: physicalBind, Guard: guard}, Port: 53}}
			target := netip.AddrPortFrom(currentTarget, 53)
			var replies atomic.Uint32
			streamCtx, stopStream := context.WithCancel(work)
			streamDone := make(chan error, 1)
			if stream {
				go func() { streamDone <- nativeStream(streamCtx, currentFactory, target, &replies) }()
				deadline := time.Now().Add(3 * time.Second)
				for replies.Load() == 0 && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				f.receipt.Before = replies.Load()
				if f.receipt.Before == 0 {
					stopStream()
					<-streamDone
					return errors.New("primary stream did not start")
				}
			}
			result, e := probe.Scan(work, probe.ScanRequest{AutoActive: true, Current: probe.CurrentDNSRequest{Target: target, Factory: currentFactory, Guard: guard}, Candidates: []probe.ScanCandidate{fresh}})
			if stream {
				f.receipt.After = replies.Load()
				stopStream()
				streamError := <-streamDone
				if !errors.Is(streamError, context.Canceled) {
					return streamError
				}
			} else {
				stopStream()
			}
			if e != nil || result.Choice == nil {
				return fmt.Errorf("no faster authenticated choice: %w", e)
			}
			if e = errors.Join(physicalFactory.Close(context.Background()), currentFactory.Close(context.Background())); e != nil {
				return e
			}
			path, e := comparisonForeignPath(luid)
			if e != nil {
				return e
			}
			known := observation.member.Load()
			if known == nil {
				return errBackendUnknown
			}
			selection = &comparisonSelection{stamp: token.Stamp(), current: *known, revision: snapshot.Revision(), index: index, digest: digest, path: path, member: member, choice: result.Choice, fresh: fresh}
			return nil
		})
		return selection, err
	}
	f.receipt.Phase = "scan-current-stream-under-restrictive-WFP"
	selection, err := scan(1, first.target, true)
	if err != nil {
		return err
	}
	if f.receipt.After <= f.receipt.Before {
		return errors.New("primary stream stopped during candidate")
	}
	oldEngine := engine
	f.receipt.Phase = "actual-selected-owner-transaction"
	if err = owner.apply(selection); err != nil {
		return err
	}
	if engine == oldEngine || observation.member.Load() == nil || observation.member.Load().Index != 1 || !observation.ready.Load() {
		return errors.New("selected backend not confirmed")
	}
	if err = waitStable(); err != nil {
		return err
	}
	if err = measure(netip.MustParseAddr("10.213.99.5")); err != nil {
		return fmt.Errorf("selected actual traffic: %w", err)
	}
	if err = verifyOwnNetwork(luid, two); err != nil {
		return err
	}
	f.receipt.Selected = true
	f.receipt.Phase = "persist-failure-exact-native-rollback"
	selection, err = scan(2, netip.MustParseAddr("10.213.99.5"), false)
	if err != nil {
		return err
	}
	injected := errors.New("synthetic persist failure")
	owner.persist = func(c *conf.Config) error {
		if c.Interface.MTU == 1410 {
			return injected
		}
		return nil
	}
	if err = owner.apply(selection); !errors.Is(err, injected) {
		return fmt.Errorf("persist failure not returned: %w", err)
	}
	if observation.member.Load() == nil || observation.member.Load().Index != 1 || !observation.ready.Load() {
		return errors.New("exact rollback membership absent")
	}
	if err = waitStable(); err != nil {
		return err
	}
	if err = measure(netip.MustParseAddr("10.213.99.5")); err != nil {
		return fmt.Errorf("rollback actual traffic: %w", err)
	}
	if err = verifyOwnNetwork(luid, two); err != nil {
		return err
	}
	f.receipt.Rollback = true
	f.receipt.Phase = "stale-choice-and-raw-edit"
	selection, err = scan(2, netip.MustParseAddr("10.213.99.5"), false)
	if err != nil {
		return err
	}
	oldEngine = engine
	gate.NotifyChange()
	if err = owner.apply(selection); err == nil || engine != oldEngine || observation.member.Load() == nil {
		return errors.New("stale choice mutated backend")
	}
	f.receipt.Stale = true
	access := &comparisonDeviceAccess{slot: slot, observation: &observation}
	if err = access.IpcSet("listen_port=0\n"); err != nil {
		return err
	}
	if observation.member.Load() != nil {
		return errors.New("raw edit retained known settings")
	}
	f.receipt.ExternalUnknown = true
	f.receipt.SameTUN = winipcfg.LUID(native.LUID()) == luid
	f.receipt.VaultPreserved = string(cipher) == string(beforeVault)
	if !f.receipt.SameTUN || !f.receipt.VaultPreserved {
		return errors.New("TUN or immutable vault changed")
	}
	f.receipt.Phase = "done"
	return nil
}

func TestNativeActualBackendOwnerSelectsAndRollsBackOnSameWintun(t *testing.T) {
	name := fmt.Sprintf("R013BackendCI-%d", time.Now().UnixNano())
	directory := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	scm, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer scm.Disconnect()
	service, err := scm.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, DisplayName: name, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "--r013-backend-fixture", name, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	defer func() {
		service.Control(svc.Stop)
		deadline := time.Now().Add(6 * time.Second)
		for time.Now().Before(deadline) {
			s, e := service.Query()
			if e != nil || s.State == svc.Stopped {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err := service.Delete(); err != nil {
			t.Error(err)
		}
	}()
	if err = service.Start(); err != nil {
		t.Fatal(err)
	}
	var receipt backendReceipt
	deadline := time.Now().Add(110 * time.Second)
	for time.Now().Before(deadline) {
		if data, e := os.ReadFile(filepath.Join(directory, "backend-receipt.json")); e == nil {
			if json.Unmarshal(data, &receipt) == nil {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !receipt.Success || !receipt.Selected || !receipt.Rollback || !receipt.Stale || !receipt.ExternalUnknown || !receipt.SameTUN || !receipt.VaultPreserved || receipt.Before == 0 || receipt.After <= receipt.Before {
		if state, e := service.Query(); e == nil {
			t.Logf("SCM state=%d win32=%d specific=%d", state.State, state.Win32ExitCode, state.ServiceSpecificExitCode)
		}
		if crash, e := os.ReadFile(filepath.Join(directory, "crash.txt")); e == nil {
			for _, line := range strings.Split(string(crash), "\n") {
				if strings.HasPrefix(line, "fatal error:") || strings.HasPrefix(line, "panic:") || (strings.Contains(line, "/tunnel/") && strings.Contains(line, ".go:")) {
					t.Log(line)
				}
			}
		}
		t.Fatalf("actual shared backend owner failed: %+v", receipt)
	}
	t.Logf("Real primary DNS %d -> %d during encrypted candidate UNDER restrictive service-SID WFP; actual shared owner selected different keys/address/DNS/MTU on SAME raw Wintun, restored exact native backend after injected persist failure, refused stale choice, invalidated membership on raw UAPI edit. In-memory persistence dependency; NOT installed owner-PC, complete hourly producer, or real seed-file persistence proof.", receipt.Before, receipt.After)
}
