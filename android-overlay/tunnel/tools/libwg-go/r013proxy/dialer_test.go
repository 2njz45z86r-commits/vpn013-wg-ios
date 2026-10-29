// SPDX-License-Identifier: MIT
package r013proxy

import (
	"context"
	xnet "github.com/xtls/xray-core/common/net"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestProtectionDenialCannotConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int32
	route := NewRoute(func(uintptr) bool { calls.Add(1); return false })
	defer route.Close()
	conn, err := route.dial(context.Background(), "tcp", listener.Addr().String())
	if err == nil || conn != nil || calls.Load() != 1 {
		t.Fatal("unprotected connection accepted")
	}
	if tcp, ok := listener.(*net.TCPListener); ok {
		_ = tcp.SetDeadline(time.Now().Add(30 * time.Millisecond))
	}
	if conn, err = listener.Accept(); err == nil {
		_ = conn.Close()
		t.Fatal("peer received denied connection")
	}
}
func TestRetirementClosesActualSocketAndRejectsLateDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	route := NewRoute(func(uintptr) bool { return true })
	conn, err := route.dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	route.Close()
	route.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write([]byte("retired")); err == nil {
		t.Fatal("retired socket remains open")
	}
	if next, err := route.dial(context.Background(), "tcp", listener.Addr().String()); err == nil {
		_ = next.Close()
		t.Fatal("late dial after retirement")
	}
	route.mu.Lock()
	defer route.mu.Unlock()
	if len(route.sockets) != 0 {
		t.Fatal("socket owner leaked")
	}
}
func TestNoDefaultResolverOrMissingRoute(t *testing.T) {
	route := NewRoute(func(uintptr) bool { t.Fatal("must refuse before socket creation"); return false })
	defer route.Close()
	for _, address := range []string{"example.org:443", "localhost:443", "127.0.0.1", "[fe80::1%zone]:443"} {
		if conn, err := route.dial(context.Background(), "tcp", address); err == nil {
			_ = conn.Close()
			t.Fatal("unresolved endpoint accepted")
		}
	}
	if _, err := (systemDialer{}).Dial(context.Background(), nil, xnet.Destination{}, nil); err == nil {
		t.Fatal("missing route accepted")
	}
}
