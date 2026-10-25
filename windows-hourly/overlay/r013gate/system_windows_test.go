// SPDX-License-Identifier: MIT
package r013gate

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
	"testing"
	"time"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"github.com/amnezia-vpn/amneziawg-windows/v3/elevate"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// This test executable acts as a short-lived SYSTEM service ONLY on disposable
// CI. No customer configuration is used. Its optional native case loads the
// verified Wintun driver only inside the disposable hosted machine.
func TestMain(m *testing.M) {
	if (len(os.Args) == 5 || len(os.Args) == 6) && os.Args[1] == "--r013-scm-fixture" {
		name, directory, object := os.Args[2], os.Args[3], os.Args[4]
		service, err := svc.IsWindowsService()
		if err != nil || !service || !strings.HasPrefix(name, "R013ProbeCI-") ||
			!strings.HasPrefix(object, `Global\VPN013-Probe-CI-`) || !filepath.IsAbs(directory) {
			os.Exit(20)
		}
		native := len(os.Args) == 6 && os.Args[5] == "wintun"
		if len(os.Args) == 6 && !native {
			os.Exit(24)
		}
		if svc.Run(name, &systemFixture{directory: directory, object: object, native: native}) != nil {
			os.Exit(21)
		}
		os.Exit(0)
	}
	if driver := os.Getenv("R013_CI_WINTUN_DLL"); driver != "" {
		if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" {
			os.Exit(25)
		}
		data, err := os.ReadFile(driver)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(data)) != "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce" {
			os.Exit(26)
		}
		exe, err := os.Executable()
		if err != nil {
			os.Exit(27)
		}
		if err = os.WriteFile(filepath.Join(filepath.Dir(exe), "wintun.dll"), data, 0600); err != nil {
			os.Exit(28)
		}
	}
	os.Exit(m.Run())
}

type systemReceipt struct {
	Phase             string `json:"phase,omitempty"`
	Ready             bool   `json:"ready"`
	Drained           bool   `json:"drained"`
	Success           bool   `json:"success"`
	System            bool   `json:"system"`
	SessionZero       bool   `json:"session_zero"`
	PrivilegesDropped bool   `json:"privileges_dropped"`
	VaultVerified     bool   `json:"vault_verified"`
	Echo              bool   `json:"echo"`
	Stamp             Stamp  `json:"stamp"`
	Error             string `json:"error,omitempty"`
	NativeWintun      bool   `json:"native_wintun"`
	StreamBefore      uint32 `json:"stream_before"`
	StreamAfter       uint32 `json:"stream_after"`
}
type systemFixture struct {
	directory, object string
	receipt           systemReceipt
	native            bool
}

func (f *systemFixture) write() error {
	data, err := json.Marshal(f.receipt)
	if err != nil {
		return err
	}
	temp := filepath.Join(f.directory, "receipt.pending")
	if err = os.WriteFile(temp, data, 0600); err != nil {
		return err
	}
	from, _ := windows.UTF16PtrFromString(temp)
	to, _ := windows.UTF16PtrFromString(filepath.Join(f.directory, "receipt.json"))
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

func systemIdentityAndPrivileges() (bool, bool, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return false, false, err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return false, false, err
	}
	var session uint32
	var needed uint32
	err = windows.GetTokenInformation(token, windows.TokenSessionId, (*byte)(unsafe.Pointer(&session)), 4, &needed)
	return user.User.Sid.IsWellKnown(windows.WinLocalSystemSid), err == nil && needed == 4 && session == 0, err
}
func onlyDriverPrivilegeRemains() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	var size uint32
	windows.GetTokenInformation(token, windows.TokenPrivileges, nil, 0, &size)
	if size < 4 || size > 65536 {
		return errors.New("invalid privilege inventory size")
	}
	data := make([]byte, size)
	if err := windows.GetTokenInformation(token, windows.TokenPrivileges, &data[0], size, &size); err != nil {
		return err
	}
	var driver windows.LUID
	if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeLoadDriverPrivilege"), &driver); err != nil {
		return err
	}
	values := (*windows.Tokenprivileges)(unsafe.Pointer(&data[0]))
	if values.PrivilegeCount != 1 || values.Privileges[0].Luid != driver {
		return errors.New("unexpected retained privilege")
	}
	return nil
}

func (f *systemFixture) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-finished:
			return
		case <-ctx.Done():
			return
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
	if writeErr := f.write(); writeErr != nil {
		return true, 22
	}
	changes <- svc.Status{State: svc.StopPending}
	if err != nil {
		return true, 23
	}
	return false, 0
}
func (f *systemFixture) run(ctx context.Context) error {
	system, zero, err := systemIdentityAndPrivileges()
	if err != nil {
		return err
	}
	f.receipt.System, f.receipt.SessionZero = system, zero
	if !system || !zero {
		return errors.New("fixture not SYSTEM session0")
	}
	gate, err := openNamed(f.object)
	if err != nil {
		return fmt.Errorf("Global before drop: %w", err)
	}
	defer gate.Close(context.Background())
	if err = elevate.DropAllPrivileges(true); err != nil {
		return err
	}
	if err = onlyDriverPrivilegeRemains(); err != nil {
		return err
	}
	f.receipt.PrivilegesDropped = true
	f.receipt.Phase = "post-drop"
	if err = f.write(); err != nil {
		return err
	}
	if err = proveSystemVaultRead(); err != nil {
		return err
	}
	f.receipt.VaultVerified = true
	// Reopen the same Global objects after removing privileges: existing object
	// access remains governed by the unchanged SYSTEM/Administrators DACL.
	reopened, err := openNamed(f.object)
	if err != nil {
		return fmt.Errorf("Global after drop: %w", err)
	}
	if reopened.Current() != gate.Current() {
		return errors.New("Global mapping not shared after drop")
	}
	// Closing the extra handle conservatively invalidates old measurement stamps.
	if err = reopened.Close(context.Background()); err != nil {
		return err
	}
	if f.native {
		before, after, err := runNativeWintunProof(ctx, gate, strings.TrimPrefix(f.object, `Global\VPN013-Probe-CI-`), func(phase string) error { f.receipt.Phase = phase; return f.write() })
		if err != nil {
			return err
		}
		f.receipt.NativeWintun = true
		f.receipt.StreamBefore = before
		f.receipt.StreamAfter = after
	}
	return gate.Candidate(ctx, func(work context.Context, token Token) error {
		var index uint32
		interfaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		for _, iface := range interfaces {
			if iface.Flags&net.FlagLoopback != 0 && iface.Index > 0 {
				index = uint32(iface.Index)
				break
			}
		}
		if index == 0 {
			return errors.New("missing observed loopback")
		}
		factory, err := NewUDPFactory(protectedudp.Physical, index, index, token)
		if err != nil {
			return err
		}
		defer factory.Close(context.Background())
		echo, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer echo.Close()
		go func() {
			var b [128]byte
			echo.SetReadDeadline(time.Now().Add(time.Second))
			n, from, err := echo.ReadFrom(b[:])
			if err == nil {
				echo.WriteTo(b[:n], from)
			}
		}()
		replies := make(chan string, 1)
		socket, err := factory.OpenPhysical(netip.MustParseAddrPort(echo.LocalAddr().String()), func(b []byte) { replies <- string(b) }, func() {})
		if err != nil {
			return err
		}
		socket.Write([]byte("SYSTEM-after-drop"), func(err error) {
			if err != nil {
				replies <- "error"
			}
		})
		select {
		case reply := <-replies:
			if reply != "SYSTEM-after-drop" {
				return errors.New("wrong SYSTEM echo")
			}
		case <-time.After(2 * time.Second):
			return errors.New("SYSTEM echo missing")
		}
		f.receipt.Echo = true
		f.receipt.Ready = true
		f.receipt.Stamp = token.Stamp()
		if err = f.write(); err != nil {
			return err
		}
		<-work.Done()
		if ctx.Err() != nil {
			return errors.New("parent never cancelled through Global barrier")
		}
		if token.Valid() {
			return errors.New("SYSTEM token survived cross-session primary request")
		}
		if err = factory.Close(context.Background()); err != nil {
			return err
		}
		f.receipt.Drained = true
		return f.write() // true close acknowledgement is visible before mutex release
	})
}

func runSystemFixtureTest(t *testing.T, native bool) {
	t.Helper()
	requireCI(t)
	local := testName(t)
	nonce := strings.TrimPrefix(local, `Local\VPN013-Probe-CI-`)
	name := "R013ProbeCI-" + nonce
	object := `Global\VPN013-Probe-CI-` + nonce
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
	args := []string{"--r013-scm-fixture", name, directory, object}
	if native {
		args = append(args, "wintun")
	}
	// Match the real tunnel installer: WFP's process-security descriptor requires
	// the service SID. A bare SYSTEM token alone is not the same native context.
	service, err := scm.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, DisplayName: name, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, args...)
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
		if e := service.Delete(); e != nil {
			t.Error(e)
		}
	}()
	if err = service.Start(); err != nil {
		t.Fatal(err)
	}
	read := func() systemReceipt {
		var receipt systemReceipt
		data, e := os.ReadFile(filepath.Join(directory, "receipt.json"))
		if e == nil {
			json.Unmarshal(data, &receipt)
		}
		return receipt
	}
	deadline := time.Now().Add(40 * time.Second)
	var receipt systemReceipt
	for time.Now().Before(deadline) {
		receipt = read()
		if receipt.Error != "" {
			t.Fatal(receipt.Error)
		}
		if receipt.Ready {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !receipt.Ready || !receipt.System || !receipt.SessionZero || !receipt.PrivilegesDropped || !receipt.Echo || !receipt.VaultVerified {
		t.Fatalf("SYSTEM proof missing: %+v", receipt)
	}
	gate := testGate(t, object)
	if gate.Current() != receipt.Stamp {
		t.Fatal("cross-session mapping disagrees")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err = gate.Primary(ctx, Stamp{}, func(context.Context) error {
		if !read().Drained {
			return errors.New("primary entered before SYSTEM socket drain")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		receipt = read()
		if receipt.Error != "" {
			t.Fatal(receipt.Error)
		}
		if receipt.Success {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !receipt.Success || !receipt.Drained {
		t.Fatalf("SYSTEM completion missing: %+v", receipt)
	}
	if native && (!receipt.NativeWintun || receipt.StreamBefore == 0 || receipt.StreamAfter <= receipt.StreamBefore) {
		t.Fatalf("Native Wintun current/candidate proof missing: %+v", receipt)
	}
	if native {
		t.Logf("Real Wintun DNS stream %d -> %d during separate AWG candidate; native primary unchanged; same-method choice and active-alias exclusion confirmed", receipt.StreamBefore, receipt.StreamAfter)
		t.Log("Exclusive native TUN leases survived real primary engine retirement; fresh backend reset omitted obfuscation fields, preserved identity and same TUN, authenticated DNS again after actual privilege drop")
		t.Log("Actual upstream WFP sessions recreated after unchanged privilege drop: permissive, restrictive with DNS rules, permissive; each dynamic session immediately closed on disposable runner")
	}
	t.Log("SCM SYSTEM/session0 created Global barrier before actual DropAllPrivileges(true); post-drop reopen, pinned UDP echo, cross-session cancellation and real-close drain confirmed")
}

func TestGlobalSystemServiceKeepsBarrierAfterRealPrivilegeDrop(t *testing.T) {
	runSystemFixtureTest(t, false)
}
func TestNativeWintunCurrentTrafficContinuesDuringOtherAWGScan(t *testing.T) {
	requireCI(t)
	if os.Getenv("R013_CI_WINTUN_DLL") == "" {
		t.Fatal("Verified official Wintun payload is required, never skip")
	}
	runSystemFixtureTest(t, true)
}
