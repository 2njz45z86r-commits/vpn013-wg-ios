// SPDX-License-Identifier: MIT
package r013gate

import (
	"bufio"
	"context"
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedPrimaryUAPIPreservesReadsAndCannotOwnFenceWhileReadingBody(t *testing.T) {
	requireCI(t)
	for _, scenario := range []string{"read-only-get", "partial-set", "cancel-during-fenced-set", "bounded-workers-and-operation"} {
		t.Run(scenario, func(t *testing.T) {
			gate := testGate(t, testName(t))
			var sets atomic.Uint32
			memory := &nativeDNSPeer{outbound: make(chan []byte, 1), events: make(chan tun.Event, 1), done: make(chan struct{})}
			primary := device.NewDevice(memory, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
			defer primary.Close()
			primary.SetPrimaryMutationFence(func(work func() error) error {
				return gate.Primary(context.Background(), Stamp{}, func(context.Context) error { sets.Add(1); return work() })
			})
			server, err := NewPrimaryUAPIServer(context.Background(), primary)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close(context.Background())
			client, pipe := net.Pipe()
			defer client.Close()
			if !server.Serve(pipe) {
				t.Fatal("initial connection refused")
			}
			switch scenario {
			case "read-only-get":
				before := gate.Current()
				if _, err = client.Write([]byte("get=1\n\n")); err != nil {
					t.Fatal(err)
				}
				client.SetReadDeadline(time.Now().Add(time.Second))
				reader := bufio.NewReader(client)
				var output strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						t.Fatal(err)
					}
					output.WriteString(line)
					if line == "\n" {
						break
					}
				}
				if !strings.Contains(output.String(), "errno=0\n") || gate.Current() != before || sets.Load() != 0 {
					t.Fatal("ordinary get changed primary generation or framing")
				}
			case "partial-set":
				if _, err = client.Write([]byte("set=1\nlisten_port=")); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
				if err = gate.Primary(ctx, Stamp{}, func(context.Context) error { return nil }); err != nil {
					t.Fatal("partial body owned primary barrier", err)
				}
				if sets.Load() != 0 {
					t.Fatal("partial body was executed")
				}
				if err = server.Close(ctx); err != nil {
					t.Fatal("partial body did not close and drain", err)
				}
			case "cancel-during-fenced-set":
				ready, cancelled, ack := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				defer once.Do(func() { close(ack) })
				done := make(chan error, 1)
				go func() {
					done <- gate.Candidate(context.Background(), func(ctx context.Context, _ Token) error {
						close(ready)
						<-ctx.Done()
						close(cancelled)
						<-ack
						return nil
					})
				}()
				<-ready
				if _, err = client.Write([]byte("set=1\nlisten_port=0\n\n")); err != nil {
					t.Fatal(err)
				}
				select {
				case <-cancelled:
				case <-time.After(time.Second):
					t.Fatal("complete set did not enter actual device fence")
				}
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
				defer cancel()
				if err = server.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("server reported drain before actual fenced set completed", err)
				}
				if sets.Load() != 0 {
					t.Fatal("device set ran before drain")
				}
				once.Do(func() { close(ack) })
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				ctx2, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err = server.Close(ctx2); err != nil {
					t.Fatal(err)
				}
				if sets.Load() != 1 {
					t.Fatal("actual set did not finish exactly once")
				}
			case "bounded-workers-and-operation":
				var clients []net.Conn
				defer func() {
					for _, c := range clients {
						c.Close()
					}
				}()
				for i := 1; i < maxUAPIConnections; i++ {
					a, b := net.Pipe()
					clients = append(clients, a)
					if !server.Serve(b) {
						t.Fatal("bounded worker refused valid slot")
					}
				}
				a, b := net.Pipe()
				defer a.Close()
				if server.Serve(b) {
					t.Fatal("unbounded pipe worker accepted")
				}
				client.Write([]byte(strings.Repeat("x", 40)))
				client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				var byte [1]byte
				if _, err = client.Read(byte[:]); !errors.Is(err, io.EOF) {
					t.Fatal("oversized operation was not closed immediately", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err = server.Close(ctx); err != nil {
					t.Fatal("idle bounded workers did not drain", err)
				}
			}
		})
	}
}
