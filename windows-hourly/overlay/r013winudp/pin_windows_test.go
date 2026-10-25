// SPDX-License-Identifier: MIT
package r013winudp

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func ci(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" {
		t.Fatal("Disposable native CI required; no local socket tests")
	}
}
func loopback(t *testing.T) uint32 {
	t.Helper()
	all, e := net.Interfaces()
	if e != nil {
		t.Fatal(e)
	}
	for _, i := range all {
		if i.Flags&net.FlagLoopback != 0 && i.Index > 0 {
			return uint32(i.Index)
		}
	}
	t.Fatal("No observed native loopback interface")
	return 0
}

func TestPinnedSocketReadbackAndRealIPv4IPv6Echo(t *testing.T) {
	ci(t)
	index := loopback(t)
	for _, test := range []struct {
		network, host string
		family        int
	}{{"udp4", "127.0.0.1", windows.AF_INET}, {"udp6", "::1", windows.AF_INET6}} {
		t.Run(test.network, func(t *testing.T) {
			server, e := net.ListenPacket(test.network, net.JoinHostPort(test.host, "0"))
			if e != nil {
				t.Fatal(e)
			}
			defer server.Close()
			go func() {
				buf := make([]byte, 100)
				server.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, from, e := server.ReadFrom(buf)
				if e == nil {
					server.WriteTo(buf[:n], from)
				}
			}()
			var gated atomic.Bool
			dialer := net.Dialer{ControlContext: func(ctx context.Context, network, address string, raw syscall.RawConn) error {
				if network != test.network {
					return ErrBind
				}
				var failed error
				if e := raw.Control(func(fd uintptr) { failed = Pin(fd, test.family, index) }); e != nil {
					return e
				}
				if failed == nil {
					gated.Store(true)
				}
				return failed
			}}
			connection, e := dialer.Dial(test.network, server.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer connection.Close()
			if !gated.Load() {
				t.Fatal("UDP connected without pre-connect interface pin")
			}
			connection.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = connection.Write([]byte("native-route-proof")); e != nil {
				t.Fatal(e)
			}
			buf := make([]byte, 100)
			n, e := connection.Read(buf)
			if e != nil || string(buf[:n]) != "native-route-proof" {
				t.Fatalf("Pinned echo failed: %v", e)
			}
			// Rebinding an already-connected UDP socket must be rejected.
			udp := connection.(*net.UDPConn)
			raw, e := udp.SyscallConn()
			if e != nil {
				t.Fatal(e)
			}
			var rebound error
			raw.Control(func(fd uintptr) { rebound = Pin(fd, test.family, index) })
			if !errors.Is(rebound, ErrBind) {
				t.Fatal("Connected socket was allowed to rebind")
			}
		})
	}
}

func TestUnspecifiedInterfaceDeniedBeforeConnectOrDatagram(t *testing.T) {
	ci(t)
	server, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	dialer := net.Dialer{ControlContext: func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		var denied error
		raw.Control(func(fd uintptr) { denied = Pin(fd, windows.AF_INET, 0) })
		return denied
	}}
	if c, e := dialer.Dial("udp4", server.LocalAddr().String()); e == nil || c != nil {
		if c != nil {
			c.Close()
		}
		t.Fatal("Unspecified route fell back to default")
	}
	server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 50)
	if n, _, e := server.ReadFrom(buf); e == nil || n != 0 {
		t.Fatal("Denied socket emitted a datagram")
	}
}

func TestUnsupportedSocketAndFamilyFailClosed(t *testing.T) {
	ci(t)
	index := loopback(t)
	if Pin(0, windows.AF_INET, index) == nil || Pin(uintptr(windows.InvalidHandle), windows.AF_INET, index) == nil {
		t.Fatal("Invalid descriptor accepted")
	}
	if Pin(1, windows.AF_INET, 1<<24) == nil || Pin(1, windows.AF_UNIX, index) == nil {
		t.Fatal("Unsupported explicit route accepted")
	}
	dialer := net.Dialer{ControlContext: func(ctx context.Context, network, address string, raw syscall.RawConn) error {
		var denied error
		raw.Control(func(fd uintptr) { denied = Pin(fd, windows.AF_INET, index) })
		return denied
	}}
	if c, e := dialer.Dial("tcp4", "127.0.0.1:9"); e == nil || !errors.Is(e, ErrBind) {
		if c != nil {
			c.Close()
		}
		t.Fatalf("Non-UDP socket was not refused before connect: %v", e)
	}
}
