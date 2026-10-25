// SPDX-License-Identifier: MIT
package r013gate

import (
	"context"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestActualPrimaryAPIsFenceBeforeInternalLocksAndWaitForRealUDPDrain(t *testing.T) {
	requireCI(t)
	for _, operation := range []string{"Up", "Down", "IpcSetOperation", "Close"} {
		t.Run(operation, func(t *testing.T) {
			gate := testGate(t, testName(t))
			memory := &nativeDNSPeer{outbound: make(chan []byte, 1), events: make(chan tun.Event, 1), done: make(chan struct{})}
			primary := device.NewDevice(memory, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
			defer primary.Close()
			var entered atomic.Uint32
			fence := func(work func() error) error {
				return gate.Primary(context.Background(), Stamp{}, func(context.Context) error { entered.Add(1); return work() })
			}
			if !primary.SetPrimaryMutationFence(fence) || primary.SetPrimaryMutationFence(fence) || primary.SetPrimaryMutationFence(nil) {
				t.Fatal("primary fence install was replaceable")
			}
			if operation != "Up" {
				if err := primary.Up(); err != nil {
					t.Fatal(err)
				}
			}
			count := entered.Load()
			ready, cancelled, ack := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(ack) })
			scanDone := make(chan error, 1)
			go func() {
				scanDone <- gate.Candidate(context.Background(), func(ctx context.Context, token Token) error {
					// Explicit loopback socket; no datagram is sent. Its actual close must
					// complete before the public AWG lifecycle method can enter its internals.
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
					factory, err := NewUDPFactory(protectedudp.Physical, index, 0, token)
					if err != nil {
						return err
					}
					defer factory.Close(context.Background())
					server, err := net.ListenPacket("udp4", "127.0.0.1:0")
					if err != nil {
						return err
					}
					defer server.Close()
					if _, err = factory.OpenPhysical(netip.MustParseAddrPort(server.LocalAddr().String()), func([]byte) {}, func() {}); err != nil {
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
			case err := <-scanDone:
				t.Fatal(err)
			case <-time.After(time.Second):
				t.Fatal("candidate not ready")
			}
			mutation := make(chan error, 1)
			go func() {
				switch operation {
				case "Up":
					mutation <- primary.Up()
				case "Down":
					mutation <- primary.Down()
				case "IpcSetOperation":
					mutation <- primary.IpcSet("listen_port=0\n")
				case "Close":
					primary.Close()
					mutation <- nil
				}
			}()
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("primary method did not invalidate candidate")
			}
			select {
			case <-mutation:
				t.Fatal("primary method bypassed candidate drain")
			case <-time.After(30 * time.Millisecond):
			}
			if entered.Load() != count {
				t.Fatal("primary internals entered before drain")
			}
			once.Do(func() { close(ack) })
			if err := <-scanDone; err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-mutation:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("native AWG API deadlocked")
			}
			if entered.Load() != count+1 {
				t.Fatal("primary API fence not observed exactly once")
			}
			if operation == "Close" {
				select {
				case <-primary.Wait():
				default:
					t.Fatal("actual device did not close")
				}
			}
		})
	}
}
