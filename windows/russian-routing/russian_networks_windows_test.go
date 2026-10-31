// SPDX-License-Identifier: MIT
package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"github.com/amnezia-vpn/amneziawg-windows/v3/elevate"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var russianFixtureService bool

func fixtureSelectedTarget(child bool, target, selected string) bool {
	return child && target != "" && target == selected
}

// WFP intentionally requires the actual unrestricted service SID. A normal
// runner process cannot stand in for that production identity.
func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == "--r013-ru-fixture" {
		name, directory := os.Args[2], os.Args[3]
		service, err := svc.IsWindowsService()
		if err != nil || !service || !strings.HasPrefix(name, "R013RussianCI-") || !filepath.IsAbs(directory) {
			os.Exit(20)
		}
		var token windows.Token
		if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token) != nil {
			os.Exit(21)
		}
		user, err := token.GetTokenUser()
		token.Close()
		if err != nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
			os.Exit(22)
		}
		f, err := os.Create(filepath.Join(directory, "result.txt"))
		if err != nil {
			os.Exit(23)
		}
		os.Stdout, os.Stderr = f, f
		log.SetOutput(f)
		russianFixtureService = true
		os.Setenv("R013_RU_NATIVE_MODE", "worker")
		os.Setenv("R013_RU_NATIVE_SERVICE", name)
		os.Args = []string{os.Args[0], "-test.run=^TestRussianRoutingNative$", "-test.v", "-test.timeout=85s"}
		if svc.Run(name, russianRoutingService{m: m, f: f}) != nil {
			os.Exit(24)
		}
		f.Close()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type russianRoutingService struct {
	m *testing.M
	f *os.File
}

func (s russianRoutingService) Execute(_ []string, _ <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	code := s.m.Run()
	fmt.Fprintf(s.f, "R013_RU_TEST_EXIT_%d\n", code)
	s.f.Sync()
	changes <- svc.Status{State: svc.StopPending}
	return code != 0, uint32(code)
}

// All adapters and addresses are disposable fixture-owned resources. No WAN,
// customer configuration or physical interface is read or changed.
func TestRussianRoutingNative(t *testing.T) {
	mode := os.Getenv("R013_RU_NATIVE_MODE")
	child := mode == "client" && strings.HasPrefix(os.Getenv("R013_RU_NATIVE_SERVICE"), "R013RussianCI-")
	if !russianFixtureService && !child && (os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios") {
		t.Fatal("disposable official hosted Windows runner required")
	}
	if mode == "client" {
		target := os.Getenv("R013_RU_NATIVE_TARGET")
		if target != "2.56.24.2" && target != "198.18.0.2" && target != "2001:640::2" && target != "2001:db8:130::2" {
			// Catalog-derived destination is allowed only when an exact /32 is
			// installed on this fixture's own TUN on the authorized CI runner.
			// The actual SYSTEM service may not inherit the runner process's
			// GITHUB_* environment. Require its fixture identity and exact
			// selected target here, then independently prove the /32 belongs
			// to the fixture TUN below before sending a packet.
			if !fixtureSelectedTarget(child, target, os.Getenv("R013_RU_NATIVE_SELECTED")) {
				t.Fatal("only owned synthetic targets permitted")
			}
			address, e := netip.ParseAddr(target)
			if e != nil || !address.Is4() {
				t.Fatal("invalid owned target")
			}
			adapters, e := winipcfg.GetAdaptersAddresses(windows.AF_INET, winipcfg.GAAFlagDefault)
			if e != nil {
				t.Fatal(e)
			}
			var owned winipcfg.LUID
			for _, a := range adapters {
				if a.FriendlyName() == "VPN013-RU-fixture" {
					owned = a.LUID
					break
				}
			}
			if owned == 0 {
				t.Fatal("fixture adapter not found")
			}
			rows, e := winipcfg.GetIPForwardTable2(windows.AF_INET)
			if e != nil {
				t.Fatal(e)
			}
			ok := false
			for _, row := range rows {
				n := row.DestinationPrefix.IPNet()
				p, pe := netip.ParsePrefix(n.String())
				if pe == nil && row.InterfaceLUID == owned && p == netip.PrefixFrom(address, 32) {
					ok = true
					break
				}
			}
			if !ok {
				t.Fatal("target route is not owned by fixture adapter")
			}
		}
		family := "udp4"
		if strings.Contains(target, ":") {
			family = "udp6"
		}
		c, err := net.DialTimeout(family, net.JoinHostPort(target, "13013"), 900*time.Millisecond)
		if err != nil {
			fmt.Println("blocked")
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(900 * time.Millisecond))
		_, err = c.Write([]byte("r013-ru-route"))
		if err != nil {
			fmt.Println("blocked")
			return
		}
		b := make([]byte, 64)
		n, err := c.Read(b)
		if err == nil && string(b[:n]) == "r013-ru-route" {
			fmt.Println("echo-ok")
		} else {
			fmt.Println("blocked")
		}
		return
	}
	if mode != "worker" {
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		driver, err := os.ReadFile(os.Getenv("R013_CI_WINTUN_DLL"))
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprintf("%x", sha256.Sum256(driver)) != "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce" {
			t.Fatal("unreviewed driver")
		}
		if err = os.WriteFile(filepath.Join(filepath.Dir(exe), "wintun.dll"), driver, 0600); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("R013RussianCI-%d", time.Now().UnixNano())
		directory := t.TempDir()
		scm, err := mgr.Connect()
		if err != nil {
			t.Fatal(err)
		}
		defer scm.Disconnect()
		service, err := scm.CreateService(name, exe, mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED}, "--r013-ru-fixture", name, directory)
		if err != nil {
			t.Fatal(err)
		}
		defer service.Close()
		// The worker owns a dynamic WFP policy. A failed worker must not leave
		// that policy blocking the hosted runner's diagnostics. SCM Stop is
		// not a process deadline: Execute is busy running the test body.
		defer service.Delete()
		if err = service.Start(); err != nil {
			t.Fatal(err)
		}
		var worker windows.Handle
		for until := time.Now().Add(8 * time.Second); time.Now().Before(until); time.Sleep(20 * time.Millisecond) {
			status, queryErr := service.Query()
			if queryErr != nil {
				t.Fatal("query owned fixture", queryErr)
			}
			if status.ProcessId == 0 {
				continue
			}
			worker, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, status.ProcessId)
			if err != nil {
				t.Fatal("open owned fixture process", err)
			}
			var image [32768]uint16
			size := uint32(len(image))
			if err = windows.QueryFullProcessImageName(worker, 0, &image[0], &size); err != nil || !strings.EqualFold(filepath.Clean(windows.UTF16ToString(image[:size])), filepath.Clean(exe)) {
				windows.CloseHandle(worker)
				t.Fatal("owned fixture process image mismatch", err)
			}
			break
		}
		if worker == 0 {
			t.Fatal("owned fixture process did not appear")
		}
		var deadlineReached atomic.Bool
		finished, watchdogDone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(watchdogDone)
			timer := time.NewTimer(110 * time.Second)
			defer timer.Stop()
			select {
			case <-finished:
			case <-timer.C:
				deadlineReached.Store(true)
				// The retained handle pins the exact process created by this
				// unique SCM service; PID reuse cannot target another process.
				windows.TerminateProcess(worker, 124)
			}
		}()
		defer func() {
			close(finished)
			<-watchdogDone
			defer windows.CloseHandle(worker)
			state, waitErr := windows.WaitForSingleObject(worker, 5000)
			if waitErr != nil || state != windows.WAIT_OBJECT_0 {
				killErr := windows.TerminateProcess(worker, 125)
				state, waitErr = windows.WaitForSingleObject(worker, 5000)
				t.Errorf("owned fixture did not exit naturally: kill=%v wait=%d/%v", killErr, state, waitErr)
			}
			if deadlineReached.Load() {
				t.Error("owned SYSTEM fixture deadline reached; incomplete proof")
			}
		}()
		var out []byte
		for until := time.Now().Add(90 * time.Second); time.Now().Before(until); time.Sleep(40 * time.Millisecond) {
			out, _ = os.ReadFile(filepath.Join(directory, "result.txt"))
			if strings.Contains(string(out), "R013_RU_TEST_EXIT_") {
				break
			}
		}
		if !strings.Contains(string(out), "R013_RU_TEST_EXIT_0") || !strings.Contains(string(out), "ACTUAL_RU_WFP_ALLOWED_FOREIGN_BLOCKED_CLEANED") || !strings.Contains(string(out), "ACTUAL_SERVICE_WFP_ONLY_BYPASS_DNS_BLOCKED_CLEANED") {
			t.Fatalf("isolated actual-SYSTEM routing service failed:\n%s", out)
		}
		t.Log(string(out))
		return
	}
	if !russianFixtureService {
		t.Fatal("worker must run in actual SCM service")
	}
	fmt.Println("R013_RU_PHASE worker-start")
	exe, _ := os.Executable()
	driver, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "wintun.dll"))
	if err != nil {
		t.Fatal("CI Wintun required", err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(driver)) != "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce" {
		t.Fatal("unreviewed Wintun")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(filepath.Dir(executable), "wintun.dll"), driver, 0600); err != nil {
		t.Fatal(err)
	}
	device, err := tun.CreateTUN("VPN013-RU-fixture", 1280)
	if err != nil {
		t.Fatal(err)
	}
	native, ok := device.(*tun.NativeTun)
	if !ok {
		device.Close()
		t.Fatal("native Wintun required")
	}
	defer native.Close()
	fmt.Println("R013_RU_PHASE owned-tun-created")
	luid := winipcfg.LUID(native.LUID())
	// Match production interface initialization. In particular a synthetic
	// echo fixture does not implement IPv6 neighbor discovery/router adverts.
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		ipif, e := luid.IPInterface(family)
		if e != nil {
			t.Fatal("fixture IP interface", family, e)
		}
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		if e = ipif.Set(); e != nil {
			t.Fatal("fixture initialize IP interface", family, e)
		}
	}
	addresses := []net.IPNet{{IP: net.ParseIP("2.56.24.1").To4(), Mask: net.CIDRMask(32, 32)}, {IP: net.ParseIP("198.18.0.1").To4(), Mask: net.CIDRMask(32, 32)}}
	if err = luid.SetIPAddressesForFamily(windows.AF_INET, addresses); err != nil {
		t.Fatal(err)
	}
	defer luid.FlushRoutes(windows.AF_INET)
	defer luid.FlushIPAddresses(windows.AF_INET)
	cat, e := r013routing.OwnerCatalog()
	if e != nil {
		t.Fatal(e)
	}
	selection := r013routing.ServiceSelection{Mode: r013routing.ServicesOnly}
	var chosen netip.Addr
	for _, service := range cat.DisplayServices() {
		if !cat.SupportsWireGuard(service.ID) {
			continue
		}
		selection.Only = []string{service.ID}
		plan, pe := cat.Resolve(selection)
		if pe != nil {
			t.Fatal(pe)
		}
		if len(plan.Networks) == 0 {
			continue
		}
		conflict := false
		for _, n := range plan.Networks {
			if n.Contains(netip.MustParseAddr("2.56.24.2")) || n.Contains(netip.MustParseAddr("9.9.9.9")) {
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		chosen = plan.Networks[0].Addr()
		break
	}
	if !chosen.IsValid() {
		t.Fatal("no eligible service policy fixture")
	}
	var routes []*winipcfg.RouteData
	for _, ip := range []string{"2.56.24.2", "198.18.0.2", chosen.String()} {
		routes = append(routes, &winipcfg.RouteData{Destination: net.IPNet{IP: net.ParseIP(ip).To4(), Mask: net.CIDRMask(32, 32)}, NextHop: net.IPv4zero})
	}
	if err = luid.SetRoutesForFamily(windows.AF_INET, routes); err != nil {
		t.Fatal(err)
	}
	addresses6 := []net.IPNet{{IP: net.ParseIP("2001:640::1"), Mask: net.CIDRMask(128, 128)}, {IP: net.ParseIP("2001:db8:130::1"), Mask: net.CIDRMask(128, 128)}}
	if err = luid.SetIPAddressesForFamily(windows.AF_INET6, addresses6); err != nil {
		t.Fatal(err)
	}
	defer luid.FlushRoutes(windows.AF_INET6)
	defer luid.FlushIPAddresses(windows.AF_INET6)
	var routes6 []*winipcfg.RouteData
	for _, ip := range []string{"2001:640::2", "2001:db8:130::2"} {
		routes6 = append(routes6, &winipcfg.RouteData{Destination: net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(128, 128)}, NextHop: net.IPv6zero})
	}
	if err = luid.SetRoutesForFamily(windows.AF_INET6, routes6); err != nil {
		t.Fatal(err)
	}

	ready := false
	for until := time.Now().Add(8 * time.Second); time.Now().Before(until); time.Sleep(20 * time.Millisecond) {
		row, e := luid.IPAddress(addresses[0].IP)
		if e == nil && row.DadState == winipcfg.DadStatePreferred {
			v6, e6 := luid.IPAddress(addresses6[0].IP)
			if e6 == nil && v6.DadState == winipcfg.DadStatePreferred {
				ready = true
				break
			}
		}
	}
	if !ready {
		v4, e4 := luid.IPAddress(addresses[0].IP)
		v6, e6 := luid.IPAddress(addresses6[0].IP)
		t.Fatalf("fixture address not preferred: v4=%+v/%v v6=%+v/%v", v4, e4, v6, e6)
	}
	fmt.Println("R013_RU_PHASE addresses-preferred")
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		sizes := []int{0}
		for {
			n, e := native.Read([][]byte{buf}, sizes, 0)
			if e != nil {
				return
			}
			if n != 1 {
				continue
			}
			p := buf[:sizes[0]]
			if len(p) >= 48 && p[0]>>4 == 6 && p[6] == 17 && string(p[48:]) == "r013-ru-route" {
				reply := make([]byte, len(p))
				reply[0] = 0x60
				copy(reply[4:6], p[4:6])
				reply[6] = 17
				reply[7] = 64
				copy(reply[8:24], p[24:40])
				copy(reply[24:40], p[8:24])
				copy(reply[40:42], p[42:44])
				copy(reply[42:44], p[40:42])
				copy(reply[44:46], p[44:46])
				copy(reply[48:], p[48:])
				pseudo := make([]byte, 40+len(reply[40:]))
				copy(pseudo[:32], reply[8:40])
				binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(reply)-40))
				pseudo[39] = 17
				copy(pseudo[40:], reply[40:])
				check := russianFixtureChecksum(pseudo)
				if check == 0 {
					check = 65535
				}
				binary.BigEndian.PutUint16(reply[46:48], check)
				if _, e = native.Write([][]byte{reply}, 0); e != nil {
					return
				}
				continue
			}
			if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 {
				continue
			}
			ihl := int(p[0]&15) * 4
			if ihl < 20 || len(p) < ihl+8 {
				continue
			}
			payload := p[ihl+8:]
			if string(payload) != "r013-ru-route" {
				continue
			}
			reply := make([]byte, 20+8+len(payload))
			reply[0] = 0x45
			binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
			reply[8] = 64
			reply[9] = 17
			copy(reply[12:16], p[16:20])
			copy(reply[16:20], p[12:16])
			copy(reply[20:22], p[ihl+2:ihl+4])
			copy(reply[22:24], p[ihl:ihl+2])
			binary.BigEndian.PutUint16(reply[24:26], uint16(8+len(payload)))
			copy(reply[28:], payload)
			var sum uint32
			for i := 0; i < 20; i += 2 {
				sum += uint32(binary.BigEndian.Uint16(reply[i : i+2]))
			}
			for sum>>16 != 0 {
				sum = (sum & 65535) + (sum >> 16)
			}
			binary.BigEndian.PutUint16(reply[10:12], ^uint16(sum))
			if _, e = native.Write([][]byte{reply}, 0); e != nil {
				return
			}
		}
	}()
	defer func() {
		native.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("native fixture read did not stop")
		}
	}()
	// The requesting executable must differ from the exe permitted for service
	// maintenance traffic; sharing SYSTEM or a process name is insufficient.
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "different-routing-client.test.exe")
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(helper)
	if err != nil {
		in.Close()
		t.Fatal(err)
	}
	_, err = io.Copy(out, in)
	in.Close()
	closeErr := out.Close()
	if err != nil || closeErr != nil {
		t.Fatal("copy fixture client")
	}
	ask := func(ip string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, helper, "-test.run=^TestRussianRoutingNative$")
		c.Env = append(os.Environ(), "R013_RU_NATIVE_MODE=client", "R013_RU_NATIVE_TARGET="+ip, "R013_RU_NATIVE_SELECTED="+chosen.String())
		text, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("native client failed: %v %s", e, text)
		}
		return strings.Contains(string(text), "echo-ok")
	}
	for _, ip := range []string{"2.56.24.2", "198.18.0.2", chosen.String(), "2001:640::2", "2001:db8:130::2"} {
		if !ask(ip) {
			t.Fatalf("physical fixture control unavailable before WFP: %s", ip)
		}
	}
	fmt.Println("R013_RU_PHASE baseline-echo-complete")
	r013routing.Enable()
	if err = elevate.DropAllPrivileges(true); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err = EnableFirewall(0, false, nil); err != nil {
		t.Fatal(err)
	}
	defer DisableFirewall()
	fmt.Println("R013_RU_PHASE restrictive-policy-installed")
	if err = VerifyFirewall(); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"2.56.24.2", "2001:640::2"} {
		if !ask(ip) {
			t.Fatalf("RU exception did not admit actual independent-client packet: %s", ip)
		}
	}
	for _, ip := range []string{"198.18.0.2", "2001:db8:130::2"} {
		if ask(ip) {
			t.Fatalf("foreign independent-client packet escaped strict WFP: %s", ip)
		}
	}
	DisableFirewall()
	fmt.Println("R013_RU_PHASE restrictive-policy-closed")
	for _, ip := range []string{"2.56.24.2", "198.18.0.2", "2001:640::2", "2001:db8:130::2"} {
		if !ask(ip) {
			t.Fatalf("fixture route did not recover after cleanup: %s", ip)
		}
	}
	// Exercise the real additional ONLY WFP policy with a test-owned routed
	// DNS address and the independent helper executable. No WAN is used.
	if e = r013routing.ActivateServicePolicy(cat, selection, []netip.Addr{netip.MustParseAddr("198.18.0.2")}); e != nil {
		t.Fatal(e)
	}
	if e = EnableFirewall(0, false, nil); e != nil {
		t.Fatal(e)
	}
	if e = VerifyFirewall(); e != nil {
		t.Fatal(e)
	}
	if !ask("2.56.24.2") || ask("198.18.0.2") || ask(chosen.String()) {
		t.Fatal("service WFP direct/DNS destination policy failed")
	}
	DisableFirewall()
	selection.Mode = r013routing.ServicesBypass
	selection.Bypass = append([]string(nil), selection.Only...)
	if e = r013routing.ActivateServicePolicy(cat, selection, []netip.Addr{netip.MustParseAddr("9.9.9.9")}); e != nil {
		t.Fatal(e)
	}
	if e = EnableFirewall(0, false, nil); e != nil {
		t.Fatal(e)
	}
	if !ask(chosen.String()) || ask("198.18.0.2") {
		t.Fatal("service WFP bypass destination policy failed")
	}
	DisableFirewall()
	if e = r013routing.ActivateServicePolicy(cat, r013routing.ServiceSelection{}, nil); e != nil {
		t.Fatal(e)
	}
	if !ask("2.56.24.2") || !ask("198.18.0.2") {
		t.Fatal("service WFP cleanup failed")
	}
	t.Log("ACTUAL_SERVICE_WFP_ONLY_BYPASS_DNS_BLOCKED_CLEANED")
	t.Logf("ACTUAL_RU_WFP_ALLOWED_FOREIGN_BLOCKED_CLEANED policy install/probes %s; full %d-prefix dataset, distinct requesting exe", time.Since(started), r013routing.NetworkCount)
}

func russianFixtureChecksum(p []byte) uint16 {
	var sum uint32
	for len(p) > 1 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestServiceWFPDestinationPolicyModel(t *testing.T) {
	// SCM children may lack runner GITHUB_* variables. Identity and exact
	// target remain mandatory before the separate actual TUN route proof.
	if !fixtureSelectedTarget(true, "203.0.113.1", "203.0.113.1") || fixtureSelectedTarget(false, "203.0.113.1", "203.0.113.1") || fixtureSelectedTarget(true, "203.0.113.1", "203.0.113.2") || fixtureSelectedTarget(true, "", "") {
		t.Fatal("fixture target identity guard")
	}
	cat, err := r013routing.OwnerCatalog()
	if err != nil {
		t.Fatal(err)
	}
	sel := r013routing.ServiceSelection{Mode: r013routing.ServicesOnly}
	var chosen netip.Addr
	dns := netip.MustParseAddr("9.9.9.9")
	for _, s := range cat.DisplayServices() {
		if !cat.SupportsWireGuard(s.ID) {
			continue
		}
		sel.Only = []string{s.ID}
		p, e := cat.Resolve(sel)
		if e == nil && len(p.Networks) > 0 {
			if e = r013routing.ActivateServicePolicy(cat, sel, []netip.Addr{dns}); e == nil {
				chosen = p.Networks[0].Addr()
				break
			}
		}
	}
	if !chosen.IsValid() {
		t.Fatal("no supported service")
	}
	defer r013routing.ActivateServicePolicy(cat, r013routing.ServiceSelection{}, nil)
	rows, err := serviceFirewallNetworks()
	if err != nil {
		t.Fatal(err)
	}
	contains := func(a netip.Addr) bool {
		for _, p := range rows {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if contains(chosen) || contains(dns) {
		t.Fatal("selected service or VPN DNS permitted directly")
	}
	old, e := r013routing.Networks()
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, p := range old {
		if p.Addr().Is6() {
			found = true
			if !contains(p.Addr()) {
				t.Fatal("existing IPv6 WFP exemption lost")
			}
			break
		}
	}
	if !found {
		t.Fatal("missing IPv6 baseline")
	}
}
