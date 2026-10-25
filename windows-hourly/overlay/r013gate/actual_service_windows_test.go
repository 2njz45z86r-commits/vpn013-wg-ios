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
			go func() {
				done <- gate.Candidate(context.Background(), func(ctx context.Context, token Token) error {
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
				ipif, err := luid.IPInterface(windows.AF_INET)
				if err != nil {
					t.Fatal(err)
				}
				ipif.NLMTU--
				if err = ipif.Set(); err != nil {
					t.Fatal(err)
				}
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
