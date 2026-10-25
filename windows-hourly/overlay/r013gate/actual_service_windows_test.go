// SPDX-License-Identifier: MIT
package r013gate

// The compiled client is exercised ONLY in disposable GitHub-hosted CI. The
// app is not installed with MSI; an ephemeral real tunnel service is created,
// read through its existing protected pipe, then stopped/deleted. Its keys and
// one /32 route are generated for this fixture and excluded from artifacts.
import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc/namedpipe"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureConfig(config string) string {
	field := func(key string) string {
		for _, line := range strings.Split(config, "\n") {
			if strings.HasPrefix(line, key+"=") {
				return strings.TrimPrefix(line, key+"=")
			}
		}
		return ""
	}
	decode := func(key string) string {
		b, _ := hex.DecodeString(field(key))
		return base64.StdEncoding.EncodeToString(b)
	}
	return "[Interface]\nPrivateKey = " + decode("private_key") + "\nAddress = 10.213.99.2/32\nJc = 3\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 30\nH1 = 1001\nH2 = 1002\nH3 = 1003\nH4 = 1004\n[Peer]\nPublicKey = " + decode("public_key") + "\nEndpoint = " + field("endpoint") + "\nAllowedIPs = 10.213.99.1/32\nPersistentKeepalive = 1\n"
}
func actualPipe(name string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	return namedpipe.DialContext(ctx, `\\.\pipe\ProtectedPrefix\Administrators\VPN013WG\`+name)
}
func actualRuntime(name string) (string, error) {
	pipe, err := actualPipe(name)
	if err != nil {
		return "", err
	}
	defer pipe.Close()
	pipe.SetDeadline(time.Now().Add(time.Second))
	if _, err = pipe.Write([]byte("get=1\n\n")); err != nil {
		return "", err
	}
	reader := bufio.NewReader(pipe)
	var result strings.Builder
	for result.Len() < maxUAPIBytes {
		line, err := boundedUAPILine(reader, maxUAPIBytes-result.Len())
		if err != nil {
			return "", err
		}
		if line == "\n" {
			if !strings.Contains(result.String(), "errno=0\n") {
				return "", errors.New("protected pipe returned failure")
			}
			return result.String(), nil
		}
		result.WriteString(line)
	}
	return "", errors.New("runtime pipe response exceeded bound")
}

func TestActualClientTunnelServicePreservesTrafficAndFencesPathSetStop(t *testing.T) {
	requireCI(t)
	client := os.Getenv("R013_CI_CLIENT_EXE")
	if client == "" || !filepath.IsAbs(client) {
		t.Fatal("disposable compiled client required, never owner installation")
	}
	if _, err := os.Stat(client); err != nil {
		t.Fatal(err)
	}
	nonce := strings.TrimPrefix(testName(t), `Local\VPN013-Probe-CI-`)
	name := "R013CI" + nonce[:12]
	physicalIndex, physical, err := observeCIPhysical()
	if err != nil {
		t.Fatal(err)
	}
	primary, err := newNativePeer(physical, netip.MustParseAddr("10.213.99.2"), 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.device.Close()
	other, err := newNativePeer(physical, netip.MustParseAddr("10.213.98.2"), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer other.device.Close()
	file := filepath.Join(t.TempDir(), name+".conf")
	if err = os.WriteFile(file, []byte(fixtureConfig(primary.config)), 0600); err != nil {
		t.Fatal(err)
	}
	install := exec.Command(client, "/installtunnelservice", file)
	if err = install.Run(); err != nil {
		t.Fatal("actual client service installation failed", err)
	}
	defer exec.Command(client, "/uninstalltunnelservice", name).Run()
	scm, err := mgr.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer scm.Disconnect()
	service, err := scm.OpenService("VPN013WGTunnel$" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	deadline := time.Now().Add(20 * time.Second)
	var actual string
	var iface *net.Interface
	for time.Now().Before(deadline) {
		actual, err = actualRuntime(name)
		iface, _ = net.InterfaceByName("VPN013-" + name)
		status, _ := service.Query()
		if err == nil && iface != nil && iface.Index > 0 && status.State == svc.Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || iface == nil || iface.Index <= 0 {
		t.Fatal("actual tunnel runtime/interface was not observed", err)
	}
	time.Sleep(350 * time.Millisecond) // initial route/interface notification burst drains
	gate, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close(context.Background())
	// SCM Running and an existing adapter do not establish that IPv4 DAD and
	// the asynchronous address/route watcher have finished. Observe those OS
	// facts before opening any candidate or current socket; never guess ready.
	readyUntil := time.Now().Add(10 * time.Second)
	var preferred, routeReady bool
	for time.Now().Before(readyUntil) {
		luid, lookupError := winipcfg.LUIDFromIndex(uint32(iface.Index))
		if lookupError == nil {
			address, addressError := luid.IPAddress(net.ParseIP(primary.source.String()).To4())
			preferred = addressError == nil && address.DadState == winipcfg.DadStatePreferred
			_, routeError := luid.Route(net.IPNet{IP: net.ParseIP(primary.target.String()).To4(), Mask: net.CIDRMask(32, 32)}, net.IPv4zero)
			routeReady = routeError == nil
		}
		if preferred && routeReady {
			stamp := gate.Current()
			time.Sleep(300 * time.Millisecond)
			if stamp == gate.Current() {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !preferred || !routeReady {
		t.Fatal("actual primary address/DAD/route never became ready", preferred, routeReady)
	}
	actual, err = actualRuntime(name)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := probe.NewActiveGuard(probe.ActiveState{Known: true, Configuration: actual})
	if err != nil {
		t.Fatal(err)
	}
	imageDigest, err := ExecutableDigest(client)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("observe-census", func(t *testing.T) {
		err := gate.Candidate(context.Background(), func(ctx context.Context, token Token) error {
			before := token.Stamp()
			snapshot, err := InspectPrimary(ctx, token, imageDigest, name)
			if err != nil {
				return err
			}
			if snapshot.Observation.TunnelIndex != uint32(iface.Index) || snapshot.Observation.Physical4 == 0 || snapshot.Observation.PID == uint32(os.Getpid()) || snapshot.Membership == "" || snapshot.RuntimeConfiguration() == "" {
				return errors.New("actual metadata/census is incomplete")
			}
			if gate.Current() != before || !token.Valid() {
				return errors.New("read-only observation mutated the shared generation")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unsupported-stopped-definition", func(t *testing.T) {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		definition, err := scm.CreateService("vpn013wgtunnel$R013Old"+nonce[:6], exe, mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS}, "/tunnelservice", file)
		if err != nil {
			t.Fatal(err)
		}
		defer definition.Close()
		defer definition.Delete()
		err = gate.Candidate(context.Background(), func(ctx context.Context, token Token) error {
			if _, err := InspectPrimary(ctx, token, imageDigest, name); !errors.Is(err, ErrCensus) {
				return errors.New("old stopped executable could bypass census")
			}
			status, err := service.Query()
			if err != nil || status.State != svc.Running {
				return errors.New("census refusal stopped the working primary")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("multiple-running-services", func(t *testing.T) {
		secondName := "R013Dual" + nonce[:10]
		secondFile := filepath.Join(t.TempDir(), secondName+".conf")
		contents := strings.Replace(fixtureConfig(other.config), "Address = 10.213.99.2/32", "Address = 10.213.98.2/32", 1)
		if err = os.WriteFile(secondFile, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if err = exec.Command(client, "/installtunnelservice", secondFile).Run(); err != nil {
			t.Fatal("second isolated service install", err)
		}
		second, err := scm.OpenService(ownServicePrefix + secondName)
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			second.Control(svc.Stop)
			deadline := time.Now().Add(8 * time.Second)
			for time.Now().Before(deadline) {
				status, e := second.Query()
				if e == nil && status.State == svc.Stopped {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}
			second.Delete()
			second.Close()
		}()
		deadline := time.Now().Add(10 * time.Second)
		running := false
		for time.Now().Before(deadline) {
			status, e := second.Query()
			if e == nil && status.State == svc.Running {
				running = true
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !running {
			t.Fatal("second service not running")
		}
		time.Sleep(350 * time.Millisecond)
		err = gate.Candidate(context.Background(), func(ctx context.Context, token Token) error {
			if _, err := InspectPrimary(ctx, token, imageDigest, name); !errors.Is(err, ErrCensus) {
				return errors.New("multiple actual primary services were guessed as one")
			}
			status, e := service.Query()
			otherStatus, e2 := second.Query()
			if e != nil || e2 != nil || status.State != svc.Running || otherStatus.State != svc.Running {
				return errors.New("census refusal stopped an existing service")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	time.Sleep(350 * time.Millisecond)
	var before, after uint32
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err = gate.Candidate(ctx, func(work context.Context, token Token) error {
		physicalFactory, err := NewUDPFactory(protectedudp.Physical, physicalIndex, 0, token)
		if err != nil {
			return err
		}
		defer physicalFactory.Close(context.Background())
		current, err := NewUDPFactory(protectedudp.ThroughTunnel, uint32(iface.Index), 0, token)
		if err != nil {
			return err
		}
		defer current.Close(context.Background())
		target := netip.AddrPortFrom(primary.target, 53)
		if _, err = probe.MeasureCurrentDNS(work, probe.CurrentDNSRequest{Target: target, Factory: current, Guard: guard}); err != nil {
			status, _ := service.Query()
			return fmt.Errorf("actual service baseline (tokenValid=%t state=%d workCancelled=%t): %w", token.Valid(), status.State, work.Err() != nil, err)
		}
		streamCtx, stop := context.WithCancel(work)
		var replies atomic.Uint32
		done := make(chan error, 1)
		go func() { done <- nativeStream(streamCtx, current, target, &replies) }()
		defer func() { stop(); <-done }()
		end := time.Now().Add(2 * time.Second)
		for replies.Load() == 0 && time.Now().Before(end) {
			time.Sleep(time.Millisecond)
		}
		before = replies.Load()
		if before == 0 {
			return errors.New("actual service stream missing")
		}
		counted := &countedPhysical{PhysicalUDPFactory: physicalFactory}
		alias, _ := probe.NewPhysicalBind(primary.endpoint, counted)
		candidate, _ := probe.NewPhysicalBind(other.endpoint, counted)
		result, err := probe.Scan(work, probe.ScanRequest{AutoActive: true, Current: probe.CurrentDNSRequest{Target: target, Factory: current, Guard: guard}, Candidates: []probe.ScanCandidate{
			{ID: "active", DNSRequest: probe.DNSRequest{Request: probe.Request{Config: actual, Source: primary.source, Target: primary.target, Bind: alias, Guard: guard}, Port: 53}},
			{ID: "other", DNSRequest: probe.DNSRequest{Request: probe.Request{Config: other.config, Source: other.source, Target: other.target, Bind: candidate, Guard: guard}, Port: 53}},
		}})
		after = replies.Load()
		if err != nil {
			return err
		}
		if !token.Valid() || after <= before || !probe.Comparable(result.Before, result.After) || result.Choice == nil || result.Choice.ID != "other" || len(result.Measurements) != 2 || result.Measurements[0].Status != "active_identity_skipped" || counted.opens.Load() != 1 {
			return errors.New("actual service current/candidate proof incomplete")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Actual compiled tunnel service kept Wintun DNS stream %d -> %d while another encrypted AWG peer was ranked; active identity opened no candidate UDP", before, after)

	for _, trigger := range []string{"path", "set", "stop"} {
		t.Run(trigger, func(t *testing.T) {
			time.Sleep(350 * time.Millisecond)
			ready, cancelled, ack := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(ack) })
			done := make(chan error, 1)
			scanContext, cancelScan := context.WithCancel(context.Background())
			finished := make(chan struct{})
			defer func() {
				cancelScan()
				once.Do(func() { close(ack) })
				select {
				case <-finished:
				case <-time.After(2 * time.Second):
					t.Error("failed race fixture did not release its owned candidate")
				}
			}()
			go func() {
				defer close(finished)
				done <- gate.Candidate(scanContext, func(ctx context.Context, token Token) error {
					factory, err := NewUDPFactory(protectedudp.Physical, physicalIndex, 0, token)
					if err != nil {
						return err
					}
					defer factory.Close(context.Background())
					if _, err = factory.OpenPhysical(other.endpoint, func([]byte) {}, func() {}); err != nil {
						return err
					}
					close(ready)
					<-ctx.Done()
					close(cancelled)
					<-ack
					return factory.Close(context.Background())
				})
			}()
			select {
			case <-ready:
			case err := <-done:
				t.Fatal(err)
			case <-time.After(2 * time.Second):
				t.Fatal("actual service race fixture did not acquire candidate")
			}
			var setter net.Conn
			switch trigger {
			case "path":
				luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
				if err != nil {
					t.Fatal(err)
				}
				// Trigger an actual default-route notification on the disposable
				// TUN without replacing any existing route. Its explicit huge
				// metric cannot beat the observed existing default, and its exact
				// row is removed on every exit. No owner PC executes this fixture.
				rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
				if err != nil {
					t.Fatal(err)
				}
				bestMetric := uint64(^uint32(0))
				found := false
				for _, row := range rows {
					if row.DestinationPrefix.PrefixLength == 0 && row.InterfaceLUID != luid {
						ipif, e := row.InterfaceLUID.IPInterface(windows.AF_INET)
						if e == nil {
							metric := uint64(row.Metric) + uint64(ipif.Metric)
							if metric < bestMetric {
								bestMetric = metric
								found = true
							}
						}
					}
				}
				if !found || bestMetric >= 1<<30 {
					t.Fatal("safe existing default route was not observed")
				}
				destination := net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
				if err = luid.AddRoute(destination, net.IPv4zero, 1<<30); err != nil {
					t.Fatal(err)
				}
				defer func() {
					row, e := luid.Route(destination, net.IPv4zero)
					if e == nil {
						if e = row.Delete(); e != nil {
							t.Error(e)
						}
					}
				}()
			case "set":
				setter, err = actualPipe(name)
				if err != nil {
					t.Fatal(err)
				}
				defer setter.Close()
				if _, err = setter.Write([]byte("set=1\nfwmark=0\n\n")); err != nil {
					t.Fatal(err)
				}
			case "stop":
				if _, err = service.Control(svc.Stop); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case <-cancelled:
			case <-time.After(2 * time.Second):
				t.Fatal("actual service did not invalidate on", trigger)
			}
			if trigger == "stop" {
				time.Sleep(50 * time.Millisecond)
				status, err := service.Query()
				if err != nil || status.State == svc.Stopped {
					t.Fatal("actual service stopped before candidate UDP acknowledged close")
				}
			}
			if setter != nil {
				setter.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
				var b [64]byte
				if _, err = setter.Read(b[:]); err == nil {
					t.Fatal("actual UAPI set finished before candidate drain")
				}
			}
			once.Do(func() { close(ack) })
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if setter != nil {
				setter.SetReadDeadline(time.Now().Add(time.Second))
				reply, err := bufio.NewReader(setter).ReadString('\n')
				if err != nil || reply != "errno=0\n" {
					t.Fatal("actual UAPI set did not finish after drain", err)
				}
			}
			if trigger == "stop" {
				deadline := time.Now().Add(8 * time.Second)
				stopped := false
				for time.Now().Before(deadline) {
					status, e := service.Query()
					if e == nil && status.State == svc.Stopped {
						stopped = true
						break
					}
					time.Sleep(25 * time.Millisecond)
				}
				if !stopped {
					t.Fatal("actual service shutdown/timer drain deadlocked")
				}
			} else {
				if _, err = actualRuntime(name); err != nil {
					t.Fatal("actual service runtime lost after", trigger, err)
				}
			}
		})
	}
}
