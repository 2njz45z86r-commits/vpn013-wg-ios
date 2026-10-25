// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"errors"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestBarrierOwnedFactoriesPinBothRolesAndDrainBeforeMutation(t *testing.T) {
	requireCI(t)
	g := testGate(t, testName(t))
	var index uint32
	all, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range all {
		if iface.Flags&net.FlagLoopback != 0 && iface.Index > 0 {
			index = uint32(iface.Index)
			break
		}
	}
	if index == 0 {
		t.Fatal("No observed loopback index")
	}
	if f, err := NewUDPFactory(protectedudp.Physical, index, index, Token{}); f != nil || err == nil {
		t.Fatal("Unowned transport accepted")
	}
	ready := make(chan struct{})
	result := make(chan error, 1)
	var stale Token
	go func() {
		result <- g.Candidate(context.Background(), func(ctx context.Context, token Token) error {
			stale = token
			for _, role := range []int{protectedudp.Physical, protectedudp.ThroughTunnel} {
				f, err := NewUDPFactory(role, index, index, token)
				if err != nil {
					return err
				}
				defer f.Close(context.Background())
				server, err := net.ListenPacket("udp4", "127.0.0.1:0")
				if err != nil {
					return err
				}
				defer server.Close()
				go func() {
					packet := make([]byte, 128)
					server.SetReadDeadline(time.Now().Add(time.Second))
					n, from, err := server.ReadFrom(packet)
					if err == nil {
						server.WriteTo(packet[:n], from)
					}
				}()
				endpoint := netip.MustParseAddrPort(server.LocalAddr().String())
				replies := make(chan string, 1)
				failed := func() {}
				if role == protectedudp.Physical {
					session, err := f.OpenPhysical(endpoint, func(p []byte) { replies <- string(p) }, failed)
					if err != nil {
						return err
					}
					session.Write([]byte("role-pinned-echo"), func(e error) {
						if e != nil {
							replies <- "write failed"
						}
					})
					if _, err := f.OpenThroughTunnel(endpoint, func([]byte) {}, failed); err == nil {
						return errors.New("physical factory changed role")
					}
				} else {
					session, err := f.OpenThroughTunnel(endpoint, func(p []byte) { replies <- string(p) }, failed)
					if err != nil {
						return err
					}
					session.Write([]byte("role-pinned-echo"), func(e error) {
						if e != nil {
							replies <- "write failed"
						}
					})
					if _, err := f.OpenPhysical(endpoint, func([]byte) {}, failed); err == nil {
						return errors.New("current factory changed role")
					}
				}
				select {
				case reply := <-replies:
					if reply != "role-pinned-echo" {
						return errors.New("wrong echo")
					}
				case <-time.After(2 * time.Second):
					return errors.New("pinned protected transport did not echo")
				}
			}
			close(ready)
			<-ctx.Done()
			if token.Valid() {
				return errors.New("primary request left route token valid")
			}
			if f, err := NewUDPFactory(protectedudp.Physical, index, index, token); f != nil || err == nil {
				return errors.New("cancelled token opened factory")
			}
			return nil // deferred Factory.Close waits all actual read/write callbacks
		})
	}()
	select {
	case <-ready:
	case err := <-result:
		t.Fatalf("Transport setup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Factory setup timed out")
	}
	// This goroutine acquires only after the two actual Factory.Close calls.
	if err := g.Primary(context.Background(), Stamp{}, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if stale.Valid() {
		t.Fatal("drained route token survived")
	}
}
