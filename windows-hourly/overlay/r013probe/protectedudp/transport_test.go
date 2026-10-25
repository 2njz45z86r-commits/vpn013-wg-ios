// SPDX-License-Identifier: MIT
package protectedudp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testGate func(int, uintptr) error

func (g testGate) Prepare(role int, fd uintptr) error { return g(role, fd) }
func listener(t *testing.T) *net.UDPConn {
	t.Helper()
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func peer(c *net.UDPConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

func TestDeniedGateAndImmutableRolesBeforeAnyUDP(t *testing.T) {
	server := listener(t)
	var called atomic.Int32
	f, _ := New(Physical, testGate(func(role int, fd uintptr) error {
		called.Add(1)
		if role != Physical || fd == 0 {
			t.Error("Wrong role/fd")
		}
		return errors.New("refused")
	}))
	if s, e := f.OpenPhysical(peer(server), func([]byte) {}, func() {}); e == nil || s != nil {
		t.Fatal("Denied socket opened")
	}
	if _, e := f.OpenThroughTunnel(peer(server), func([]byte) {}, func() {}); e == nil {
		t.Fatal("Physical factory accepted virtual role")
	}
	server.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
	if _, _, e := server.ReadFromUDP(make([]byte, 64)); e == nil {
		t.Fatal("UDP before gate approval")
	}
	if called.Load() != 1 || len(f.slots) != 0 {
		t.Fatal("Gate/socket budget mismatch")
	}
}

func TestActualConnectedEchoBurstAndAcknowledgedClose(t *testing.T) {
	server := listener(t)
	go func() {
		p := make([]byte, 2048)
		for {
			n, addr, e := server.ReadFromUDP(p)
			if e != nil {
				return
			}
			server.WriteToUDP(p[:n], addr)
		}
	}()
	f, _ := New(Physical, testGate(func(role int, fd uintptr) error { return nil }))
	got := make(chan byte, 6)
	s, e := f.OpenPhysical(peer(server), func(p []byte) { got <- p[0] }, func() {})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 6; i++ {
		s.Write([]byte{byte(i)}, func(e error) {
			if e != nil {
				t.Error(e)
			}
		})
		select {
		case b := <-got:
			if b != byte(i) {
				t.Fatal("Burst reordered")
			}
		case <-time.After(time.Second):
			t.Fatal("No actual echo")
		}
	}
	ack := false
	s.Cancel(func() { ack = true })
	if !ack || len(f.slots) != 0 {
		t.Fatal("Close acknowledged before socket release")
	}
	s.Write([]byte{1}, func(e error) {
		if e == nil {
			t.Fatal("Write after close")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if f.Close(ctx) != nil {
		t.Fatal("Factory did not drain")
	}
	if _, e := f.OpenPhysical(peer(server), func([]byte) {}, func() {}); e == nil {
		t.Fatal("Reopened invalidated factory")
	}
}

func TestInvalidationWaitsForInFlightPlatformGate(t *testing.T) {
	server := listener(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f, _ := New(ThroughTunnel, testGate(func(role int, fd uintptr) error { close(entered); <-release; return nil }))
	var worker sync.WaitGroup
	worker.Add(1)
	go func() {
		defer worker.Done()
		s, e := f.OpenThroughTunnel(peer(server), func([]byte) {}, func() {})
		if e == nil || s != nil {
			t.Error("Late gate opened after invalidation")
		}
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if f.Close(ctx) == nil {
		t.Fatal("Close invented acknowledgement before platform callback completed")
	}
	close(release)
	worker.Wait()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if f.Close(ctx2) != nil || len(f.slots) != 0 {
		t.Fatal("Late gate did not actually drain")
	}
}
