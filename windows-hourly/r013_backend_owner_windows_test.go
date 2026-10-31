// SPDX-License-Identifier: MIT
package tunnel

import (
	"context"
	"crypto/sha256"
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
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type backendReceipt struct {
	Success                                                                                                         bool
	Phase, Error                                                                                                    string
	Selected, Rollback, Stale, ExternalUnknown, SameTUN, VaultPreserved, StopWins, EndpointPhysical, EndpointTunnel bool
	Before, After                                                                                                   uint32
}
type backendFixture struct {
	directory string
	stop      bool
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
	c, err := conf.FromUAPI(strings.NewReader(peer.config+"\n"), seed)
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
	// Only this disposable fixture process uses a temporary secure-store root.
	// Exercise the REAL DPAPI writer/loader, not a second persistence format.
	conf.PresetRootDirectory(f.directory)
	if err = os.WriteFile(filepath.Join(f.directory, "r013-auto.dat"), cipher, 0600); err != nil {
		return err
	}
	sourceHashes := make(map[string]string)
	for _, c := range []*conf.Config{one, two, three} {
		if err = c.Save(true); err != nil {
			return err
		}
		path, e := c.Path()
		if e != nil {
			return e
		}
		data, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		sourceHashes[path] = fmt.Sprintf("%x", sha256.Sum256(data))
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
	f.receipt.Phase = "native-physical-endpoint-DNS"
	if err = fixturePhysicalEndpointDNS(ctx, gate, physicalIndex, physical); err != nil {
		return err
	}
	f.receipt.EndpointPhysical = true

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
	if err = working.Save(true); err != nil {
		return err
	}
	// Bootstrap the SAME real implementation used by selected and rollback paths.
	var observation comparisonServiceObservation
	owner := &comparisonBackendOwner{ctx: ctx, gate: gate, relay: relay, native: native, configuration: &configuration, engine: &engine, watcher: &watcher, observation: &observation, load: r013vault.Load, persist: func(c *conf.Config) error { return c.Save(true) }}
	f.receipt.Phase = "restrictive-primary-bootstrap"
	uapi, err := working.ToUAPI()
	if err != nil {
		return err
	}
	if err = gate.Primary(ctx, r013gate.Stamp{}, func(context.Context) error { return owner.install(&working, uapi, false) }); err != nil {
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
			resolver, e := r013prepare.NewTunnelEndpointResolver(netip.AddrPortFrom(currentTarget, 53), currentFactory, false)
			if e != nil {
				return e
			}
			addresses, e := resolver.LookupNetIP(work, "ip", "peer-fixture.invalid")
			if e != nil || len(addresses) != 1 || addresses[0] != physical || resolver.TTL("peer-fixture.invalid") != 60*time.Second {
				return errors.New("actual through-Wintun endpoint resolution failed")
			}
			f.receipt.EndpointTunnel = true
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
			selection = &comparisonSelection{created: time.Now(), stamp: token.Stamp(), current: *known, revision: snapshot.Revision(), index: index, digest: digest, path: path, member: member, choice: result.Choice, fresh: fresh}
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
	stored, e := conf.LoadFromName("R013-Auto")
	if e != nil {
		return e
	}
	storedDigest, e := r013vault.WorkingDigest(*stored)
	expectedDigest, _ := r013vault.WorkingDigest(*two)
	if e != nil || storedDigest != expectedDigest {
		return errors.New("selected secure seed readback differs")
	}
	f.receipt.Selected = true
	if f.stop {
		f.receipt.Phase = "manual-SCM-stop-during-persist"
		selection, err = scan(2, netip.MustParseAddr("10.213.99.5"), false)
		if err != nil {
			return err
		}
		owner.persist = func(c *conf.Config) error {
			if err := c.Save(true); err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(f.directory, "stop-persist-ready"), []byte("ready"), 0600); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		}
		if err = owner.apply(selection); err == nil || ctx.Err() == nil || observation.ready.Load() || observation.member.Load() != nil {
			return errors.New("manual SCM stop was undone or acknowledged as successful selection")
		}
		if _, e := slot.Observe(func(r013gate.PrimaryUAPIDevice) (r013gate.Observation, error) { return r013gate.Observation{}, nil }); e == nil {
			return errors.New("stopped backend remained available")
		}
		actualVault, e := os.ReadFile(filepath.Join(f.directory, "r013-auto.dat"))
		if e != nil || string(actualVault) != string(beforeVault) {
			return errors.New("stop changed Auto vault")
		}
		for path, want := range sourceHashes {
			data, e := os.ReadFile(path)
			if e != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != want {
				return errors.New("stop changed source profile")
			}
		}
		f.receipt.StopWins = true
		f.receipt.SameTUN = winipcfg.LUID(native.LUID()) == luid
		f.receipt.VaultPreserved = true
		f.receipt.Phase = "stopped-without-stale-ack"
		return nil
	}
	f.receipt.Phase = "persist-failure-exact-native-rollback"
	selection, err = scan(2, netip.MustParseAddr("10.213.99.5"), false)
	if err != nil {
		return err
	}
	injected := errors.New("synthetic persist failure")
	owner.persist = func(c *conf.Config) error {
		if c.Interface.MTU == 1410 {
			if err := c.Save(true); err != nil {
				return err
			}
			return injected
		}
		return c.Save(true)
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
	stored, e = conf.LoadFromName("R013-Auto")
	if e != nil {
		return e
	}
	storedDigest, e = r013vault.WorkingDigest(*stored)
	if e != nil || storedDigest != expectedDigest {
		return errors.New("rollback secure seed readback differs")
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
	actualVault, e := os.ReadFile(filepath.Join(f.directory, "r013-auto.dat"))
	if e != nil {
		return e
	}
	f.receipt.VaultPreserved = string(actualVault) == string(beforeVault)
	for path, want := range sourceHashes {
		data, e := os.ReadFile(path)
		if e != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != want {
			return errors.New("original source profile file changed")
		}
	}
	if !f.receipt.SameTUN || !f.receipt.VaultPreserved {
		return errors.New("TUN or immutable vault changed")
	}
	f.receipt.Phase = "done"
	return nil
}

func TestNativeActualBackendOwnerSelectsAndRollsBackOnSameWintun(t *testing.T) {
	runBackendFixture(t, false)
}
func TestNativeSCMStopWinsDuringActualBackendPersistence(t *testing.T) { runBackendFixture(t, true) }
func runBackendFixture(t *testing.T, stop bool) {
	t.Helper()
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
	argument := "--r013-backend-fixture"
	if stop {
		argument = "--r013-backend-stop-fixture"
	}
	service, err := scm.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, DisplayName: name, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, argument, name, directory)
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
	stopSent := false
	for time.Now().Before(deadline) {
		if stop && !stopSent {
			if _, e := os.Stat(filepath.Join(directory, "stop-persist-ready")); e == nil {
				if _, e = service.Control(svc.Stop); e != nil {
					t.Fatal(e)
				}
				stopSent = true
			}
		}
		if data, e := os.ReadFile(filepath.Join(directory, "backend-receipt.json")); e == nil {
			if json.Unmarshal(data, &receipt) == nil {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	passed := receipt.Success && receipt.Selected && receipt.SameTUN && receipt.VaultPreserved && receipt.EndpointPhysical && receipt.EndpointTunnel && receipt.Before > 0 && receipt.After > receipt.Before
	if stop {
		passed = passed && stopSent && receipt.StopWins
	} else {
		passed = passed && receipt.Rollback && receipt.Stale && receipt.ExternalUnknown
	}
	if !passed {
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
	if stop {
		t.Log("Real SCM Stop during actual DPAPI seed persistence cancelled owner, left membership/slot unavailable, did not undo manual stop or acknowledge stale success, and preserved source profiles/vault.")
		return
	}
	t.Logf("Real primary DNS %d -> %d during encrypted candidate UNDER restrictive service-SID WFP; actual shared owner selected different keys/address/DNS/MTU on SAME raw Wintun, restored exact native backend after injected persist failure, refused stale choice, invalidated membership on raw UAPI edit. Real explicit physical endpoint DNS and encrypted-through-Wintun endpoint DNS with protected sockets/TTL; real temporary secure-store DPAPI seed write/readback and rollback after an injected error AFTER writing; original source ciphertext and Auto vault unchanged. NOT owner-PC or complete hourly producer proof.", receipt.Before, receipt.After)
}

func fixturePhysicalEndpointDNS(ctx context.Context, gate *r013gate.Gate, index uint32, address netip.Addr) error {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: address.AsSlice()})
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	server.SetReadDeadline(time.Now().Add(3 * time.Second))
	go func() {
		wire := make([]byte, 1232)
		n, from, e := server.ReadFromUDP(wire)
		if e != nil {
			done <- e
			return
		}
		var message dnsmessage.Message
		if message.Unpack(wire[:n]) != nil || len(message.Questions) != 1 {
			done <- errors.New("native physical DNS malformed query")
			return
		}
		message.Response = true
		message.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: message.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: address.As4()}}}
		reply, e := message.Pack()
		if e == nil {
			_, e = server.WriteToUDP(reply, from)
		}
		done <- e
	}()
	err = gate.Candidate(ctx, func(work context.Context, token r013gate.Token) error {
		factory, e := r013gate.NewUDPFactory(protectedudp.Physical, index, 0, token)
		if e != nil {
			return e
		}
		defer factory.Close(context.Background())
		target := netip.AddrPortFrom(address, uint16(server.LocalAddr().(*net.UDPAddr).Port))
		resolver, e := r013prepare.NewPhysicalEndpointResolver(target, factory, false)
		if e != nil {
			return e
		}
		addresses, e := resolver.LookupNetIP(work, "ip", "peer-fixture.invalid")
		if e != nil || len(addresses) != 1 || addresses[0] != address || resolver.TTL("peer-fixture.invalid") != 60*time.Second {
			return errors.New("actual physical endpoint DNS failed")
		}
		return nil
	})
	server.Close()
	return errors.Join(err, <-done)
}
