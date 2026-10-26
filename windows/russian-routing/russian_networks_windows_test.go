// SPDX-License-Identifier: MIT
package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/sys/windows"
)

// All adapters and addresses are disposable fixture-owned resources. No WAN,
// customer configuration or physical interface is read or changed.
func TestRussianRoutingNative(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" {
		t.Fatal("disposable official hosted Windows runner required")
	}
	mode := os.Getenv("R013_RU_NATIVE_MODE")
	if mode == "client" {
		target := os.Getenv("R013_RU_NATIVE_TARGET")
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
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRussianRoutingNative$", "-test.v")
		cmd.Env = append(os.Environ(), "R013_RU_NATIVE_MODE=worker")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "ACTUAL_RU_WFP_ALLOWED_FOREIGN_BLOCKED_CLEANED") {
			t.Fatalf("isolated native routing fixture failed: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	driver, err := os.ReadFile(os.Getenv("R013_CI_WINTUN_DLL"))
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
	luid := winipcfg.LUID(native.LUID())
	addresses := []net.IPNet{{IP: net.ParseIP("2.56.24.1").To4(), Mask: net.CIDRMask(32, 32)}, {IP: net.ParseIP("198.18.0.1").To4(), Mask: net.CIDRMask(32, 32)}}
	if err = luid.SetIPAddressesForFamily(windows.AF_INET, addresses); err != nil {
		t.Fatal(err)
	}
	defer luid.FlushRoutes(windows.AF_INET)
	defer luid.FlushIPAddresses(windows.AF_INET)
	var routes []*winipcfg.RouteData
	for _, ip := range []string{"2.56.24.2", "198.18.0.2"} {
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
		t.Fatal("fixture address not preferred")
	}
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
		c.Env = append(os.Environ(), "R013_RU_NATIVE_MODE=client", "R013_RU_NATIVE_TARGET="+ip)
		text, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("native client failed: %v %s", e, text)
		}
		return strings.Contains(string(text), "echo-ok")
	}
	for _, ip := range []string{"2.56.24.2", "198.18.0.2", "2001:640::2", "2001:db8:130::2"} {
		if !ask(ip) {
			t.Fatalf("physical fixture control unavailable before WFP: %s", ip)
		}
	}
	r013routing.Enable()
	started := time.Now()
	if err = EnableFirewall(0, false, nil); err != nil {
		t.Fatal(err)
	}
	defer DisableFirewall()
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
	for _, ip := range []string{"2.56.24.2", "198.18.0.2", "2001:640::2", "2001:db8:130::2"} {
		if !ask(ip) {
			t.Fatalf("fixture route did not recover after cleanup: %s", ip)
		}
	}
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
