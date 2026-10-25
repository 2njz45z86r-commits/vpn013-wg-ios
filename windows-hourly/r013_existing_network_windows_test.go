// SPDX-License-Identifier: MIT
package tunnel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013gate"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/elevate"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 4 && (os.Args[1] == "--r013-network-fixture" || os.Args[1] == "--r013-backend-fixture" || os.Args[1] == "--r013-backend-stop-fixture" || os.Args[1] == "--r013-hourly-fixture") {
		name, directory := os.Args[2], os.Args[3]
		service, err := svc.IsWindowsService()
		if err != nil || !service || !(strings.HasPrefix(name, "R013NetworkCI-") || strings.HasPrefix(name, "R013BackendCI-") || strings.HasPrefix(name, "R013HourlyCI-")) || !filepath.IsAbs(directory) {
			os.Exit(20)
		}
		crash, err := os.Create(filepath.Join(directory, "crash.txt"))
		if err != nil {
			os.Exit(21)
		}
		err = debug.SetCrashOutput(crash, debug.CrashOptions{})
		crash.Close()
		if err != nil {
			os.Exit(22)
		}
		var handler svc.Handler = &networkFixture{directory: directory}
		if os.Args[1] == "--r013-backend-fixture" || os.Args[1] == "--r013-backend-stop-fixture" {
			handler = &backendFixture{directory: directory, stop: os.Args[1] == "--r013-backend-stop-fixture"}
		}
		if os.Args[1] == "--r013-hourly-fixture" {
			handler = &hourlyFixture{directory: directory}
		}
		if svc.Run(name, handler) != nil {
			os.Exit(23)
		}
		os.Exit(0)
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" {
		os.Exit(24)
	}
	driver, err := os.ReadFile(os.Getenv("R013_CI_WINTUN_DLL"))
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(driver)) != "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce" {
		os.Exit(25)
	}
	exe, err := os.Executable()
	if err != nil {
		os.Exit(26)
	}
	if os.WriteFile(filepath.Join(filepath.Dir(exe), "wintun.dll"), driver, 0600) != nil {
		os.Exit(27)
	}
	os.Exit(m.Run())
}

// It records binding choices; this network-owner fixture does NOT claim AWG
// packet admission. Real AWG traffic is tested separately by existing suites.
type networkBinder struct{ four, six atomic.Uint32 }

func (b *networkBinder) BindSocketToInterface4(index uint32, blackhole bool) error {
	b.four.Store(index)
	return nil
}
func (b *networkBinder) BindSocketToInterface6(index uint32, blackhole bool) error {
	b.six.Store(index)
	return nil
}

type networkReceipt struct {
	Success                                                           bool   `json:"success"`
	Phase                                                             string `json:"phase"`
	Error                                                             string `json:"error,omitempty"`
	System                                                            bool   `json:"system"`
	SessionZero                                                       bool   `json:"session_zero"`
	Dropped                                                           bool   `json:"dropped"`
	First, Second, Retired, PolicyPreserved, SameTUN, SourceImmutable bool
}
type networkFixture struct {
	directory string
	receipt   networkReceipt
}

func (f *networkFixture) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
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
	if os.WriteFile(filepath.Join(f.directory, "receipt.json"), data, 0600) != nil {
		return true, 29
	}
	changes <- svc.Status{State: svc.StopPending}
	if err != nil {
		return true, 28
	}
	return false, 0
}
func (f *networkFixture) run(ctx context.Context) error {
	f.receipt.Phase = "identity"
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	var session, needed uint32
	if err = windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &needed); err != nil {
		return err
	}
	f.receipt.System = user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
	f.receipt.SessionZero = needed == 4 && session == 0
	if !f.receipt.System || !f.receipt.SessionZero {
		return errors.New("not SYSTEM session zero")
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
	f.receipt.Dropped = true
	nativeDevice, err := tun.CreateTUN("R013NetworkCI", 1370)
	if err != nil {
		return err
	}
	defer nativeDevice.Close()
	native := nativeDevice.(*tun.NativeTun)
	luid := winipcfg.LUID(native.LUID())
	defer flushOwnNetwork(luid)
	f.receipt.Phase = "first-explicit-existing"
	first := fixtureNetworkConfig(2, 1, 1370)
	original, _ := json.Marshal(first)
	watcher, err := watchInterface(gate, ctx)
	if err != nil {
		return err
	}
	defer watcher.Destroy()
	if err = watcher.ConfigureExisting(ctx, &networkBinder{}, &first, native); err != nil {
		return err
	}
	if err = verifyOwnNetwork(luid, &first); err != nil {
		return err
	}
	f.receipt.First = true
	after, _ := json.Marshal(first)
	if string(original) != string(after) {
		return errors.New("source configuration changed")
	}
	f.receipt.SourceImmutable = true
	f.receipt.Phase = "retire-preserving-policy"
	if err = watcher.RetireForBackend(ctx); err != nil {
		return err
	}
	if err = firewall.VerifyFirewall(); err != nil {
		return fmt.Errorf("policy lost during retirement: %w", err)
	}
	if _, err = luid.IPAddress(first.Interface.Addresses[0].IP); !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return errors.New("retired source remains or readback failed")
	}
	if _, err = luid.Route(first.Peers[0].AllowedIPs[0].IPNet(), net.IPv4zero); !errors.Is(err, windows.ERROR_NOT_FOUND) {
		return errors.New("retired route remains or readback failed")
	}
	if err = verifyRetiredNetwork(luid, &first); err != nil {
		return err
	}
	f.receipt.Retired = true
	f.receipt.PolicyPreserved = true
	f.receipt.Phase = "second-explicit-same-TUN"
	second := fixtureNetworkConfig(3, 4, 1390)
	next, err := watchInterface(gate, ctx)
	if err != nil {
		return err
	}
	defer next.Destroy()
	if err = next.ConfigureExisting(ctx, &networkBinder{}, &second, native); err != nil {
		return err
	}
	if err = verifyOwnNetwork(luid, &second); err != nil {
		return err
	}
	f.receipt.Second = true
	f.receipt.SameTUN = winipcfg.LUID(native.LUID()) == luid
	if !f.receipt.SameTUN {
		return errors.New("TUN changed")
	}
	// A failed reapply cannot quietly overwrite the current watcher's owner.
	if err = next.ConfigureExisting(ctx, &networkBinder{}, &first, native); err == nil {
		return errors.New("already-owned watcher accepted overwrite")
	}
	if err = verifyOwnNetwork(luid, &second); err != nil {
		return err
	}
	f.receipt.Phase = "done"
	return nil
}
func fixtureNetworkConfig(source, target byte, mtu uint16) conf.Config {
	return conf.Config{Name: "R013-Auto", Interface: conf.Interface{Addresses: []conf.IPCidr{{IP: net.IP{10, 213, 94, source}, Cidr: 32}}, DNS: []net.IP{{10, 213, 95, target}}, DNSSearch: []string{"fixture.invalid"}, MTU: mtu}, Peers: []conf.Peer{{AllowedIPs: []conf.IPCidr{{IP: net.IP{10, 213, 95, target}, Cidr: 32}}}}}
}

func TestNativeExistingTUNNetworkRetiresAndReappliesAfterPrivilegeDrop(t *testing.T) {
	name := fmt.Sprintf("R013NetworkCI-%d", time.Now().UnixNano())
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
	service, err := scm.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, DisplayName: name, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "--r013-network-fixture", name, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	defer func() {
		service.Control(svc.Stop)
		deadline := time.Now().Add(5 * time.Second)
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
	var receipt networkReceipt
	deadline := time.Now().Add(50 * time.Second)
	for time.Now().Before(deadline) {
		if data, e := os.ReadFile(filepath.Join(directory, "receipt.json")); e == nil {
			if json.Unmarshal(data, &receipt) == nil {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !receipt.Success || !receipt.First || !receipt.Second || !receipt.Retired || !receipt.PolicyPreserved || !receipt.SameTUN || !receipt.SourceImmutable || !receipt.System || !receipt.SessionZero || !receipt.Dropped {
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
		t.Fatalf("existing network fixture failed: %+v", receipt)
	}
	t.Log("Real SYSTEM/session0 after unchanged privilege drop: existing native TUN applies preferred address/routes/DNS/MTU, genuinely retires callbacks and own network, preserves WFP, reapplies changed network on SAME raw TUN; source snapshot immutable. Recording binder only; NOT restrictive AWG packet admission, backend switch, or release proof.")
}

type failRetirement struct{ calls int }

func (f *failRetirement) Unregister() error {
	f.calls++
	if f.calls == 1 {
		return errors.New("injected unregister failure")
	}
	return nil
}
func TestWatcherRetirementKeepsFailedSubscriptionOwned(t *testing.T) {
	gate, err := r013gate.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer gate.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	subscription := &failRetirement{}
	watcher := &interfaceWatcher{comparisonGate: gate, comparisonContext: ctx, comparisonStop: cancel, changeCallbacks4: []winipcfg.ChangeCallback{subscription}}
	if err = watcher.RetireForBackend(context.Background()); err == nil || subscription.calls != 1 || len(watcher.changeCallbacks4) != 1 {
		t.Fatal("failed callback was lost")
	}
	if err = watcher.RetireForBackend(context.Background()); err != nil || subscription.calls != 2 || len(watcher.changeCallbacks4) != 0 {
		t.Fatal("callback not genuinely retried and drained", err)
	}
}

func TestExistingNetworkRequiredFamiliesPreserveIPv6Requirement(t *testing.T) {
	configuration := fixtureNetworkConfig(2, 1, 1370)
	if !networkNeedsFamily(&configuration, windows.AF_INET) || networkNeedsFamily(&configuration, windows.AF_INET6) {
		t.Fatal("wrong v4 requirements")
	}
	configuration.Interface.DNS = append(configuration.Interface.DNS, net.ParseIP("2001:db8::53"))
	if !networkNeedsFamily(&configuration, windows.AF_INET6) {
		t.Fatal("IPv6 DNS cannot be silently stripped")
	}
}
