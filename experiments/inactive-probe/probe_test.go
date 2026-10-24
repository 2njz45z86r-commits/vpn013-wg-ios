// SPDX-License-Identifier: MIT
package awgprobe

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// echoResponder receives/decrypts a real AWG packet and returns an ICMP reply;
// every key, address and UDP listener is created for this disposable local test.
type echoResponder struct {
	*memoryTun
	requests atomic.Uint64
	delay    atomic.Int64
}

func (e *echoResponder) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if offset < 0 || offset > len(b) {
			continue
		}
		p := b[offset:]
		if len(p) != 44 || p[0] != 0x45 || p[9] != 1 || p[20] != 8 {
			continue
		}
		e.requests.Add(1)
		if delay := time.Duration(e.delay.Load()); delay > 0 {
			time.Sleep(delay)
		}
		reply := append([]byte(nil), p...)
		copy(reply[12:16], p[16:20])
		copy(reply[16:20], p[12:16])
		reply[10] = 0
		reply[11] = 0
		binary.BigEndian.PutUint16(reply[10:12], checksum(reply[:20]))
		reply[20] = 0
		reply[22] = 0
		reply[23] = 0
		binary.BigEndian.PutUint16(reply[22:24], checksum(reply[20:]))
		select {
		case e.outbound <- reply:
		case <-e.done:
		}
	}
	return len(bufs), nil
}
func fixture(t *testing.T) (Request, *echoResponder) {
	t.Helper()
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientIP := netip.MustParseAddr("10.13.99.2")
	serverIP := netip.MustParseAddr("10.13.99.1")
	memory := &echoResponder{memoryTun: newMemory(serverIP, clientIP)}
	dev := device.NewDevice(memory, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	header := "jc=3\njmin=40\njmax=70\ns1=20\ns2=30\nh1=1001\nh2=1002\nh3=1003\nh4=1004\n"
	if dev.IpcSet("private_key="+hex.EncodeToString(server.Bytes())+"\nlisten_port=0\n"+header+"public_key="+hex.EncodeToString(client.PublicKey().Bytes())+"\nallowed_ip=10.13.99.2/32\n") != nil || dev.Up() != nil {
		t.Fatal("synthetic peer setup")
	}
	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal("synthetic peer status")
	}
	port := ""
	for _, s := range strings.Split(state, "\n") {
		if strings.HasPrefix(s, "listen_port=") {
			port = strings.TrimPrefix(s, "listen_port=")
		}
	}
	if port == "" || port == "0" {
		t.Fatal("synthetic peer port")
	}
	return Request{Config: "private_key=" + hex.EncodeToString(client.Bytes()) + "\nlisten_port=0\n" + header + "public_key=" + hex.EncodeToString(server.PublicKey().Bytes()) + "\nendpoint=127.0.0.1:" + port + "\nallowed_ip=10.13.99.1/32\n", Source: clientIP, Target: serverIP, Bind: conn.NewStdNetBind(), Guard: guardForTest(t, ActiveState{Known: true})}, memory
}
func TestRealAuthenticatedEcho(t *testing.T) {
	r, peer := fixture(t)
	peer.delay.Store(int64(20 * time.Millisecond))
	result, err := Measure(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Samples != 3 || result.Median < 10*time.Millisecond || peer.requests.Load() < 4 {
		t.Fatalf("missing authenticated samples: count=%d median=%s replies=%d", result.Samples, result.Median, peer.requests.Load())
	}
	t.Logf("Three authenticated in-tunnel samples, median %s", result.Median)
}
func TestWrongPeerCannotSucceed(t *testing.T) {
	r, peer := fixture(t)
	foreign, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(r.Config, "\n")
	for i, s := range lines {
		if strings.HasPrefix(s, "public_key=") {
			lines[i] = "public_key=" + hex.EncodeToString(foreign.PublicKey().Bytes())
		}
	}
	r.Config = strings.Join(lines, "\n")
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	if _, err = Measure(ctx, r); err == nil {
		t.Fatal("unauthenticated peer accepted")
	}
	if peer.requests.Load() != 0 {
		t.Fatal("foreign key delivered plaintext")
	}
}
func TestCandidateDoesNotStopIndependentActiveEngine(t *testing.T) {
	active, mainPeer := fixture(t)
	memory := newMemory(active.Source, active.Target)
	dev := device.NewDevice(memory, active.Bind, device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if dev.IpcSet(active.Config) != nil || dev.Up() != nil {
		t.Fatal("active engine setup")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := memory.echo(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := memory.echo(ctx); err != nil {
				done <- err
				return
			}
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	first := mainPeer.requests.Load()
	for i := 0; i < 4; i++ {
		candidate, _ := fixture(t)
		candidate.Guard = guardForTest(t, ActiveState{Known: true, Configuration: active.Config})
		if _, err := Measure(ctx, candidate); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if mainPeer.requests.Load() <= first {
		t.Fatal("active stream stopped during candidate probes")
	}
	cancel()
	<-done
	final, finalCancel := context.WithTimeout(context.Background(), time.Second)
	defer finalCancel()
	if _, err := memory.echo(final); err != nil {
		t.Fatal(fmt.Errorf("active stream after probes: %w", err))
	}
}

func TestActiveAliasCannotRoamTheRunningPeer(t *testing.T) {
	r, peer := fixture(t)
	r.Guard = guardForTest(t, ActiveState{Known: true, Configuration: r.Config})
	lines := strings.Split(r.Config, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "private_key=") {
			key, _ := hex.DecodeString(strings.TrimPrefix(line, "private_key="))
			key[0] ^= 7
			key[31] ^= 192 // Same X25519 public identity after clamping.
			lines[i] = "private_key=" + hex.EncodeToString(key)
		}
		if strings.HasPrefix(line, "endpoint=") {
			lines[i] = "endpoint=127.0.0.1:1"
		}
	}
	r.Config = strings.Join(lines, "\n")
	if _, err := Measure(context.Background(), r); !errors.Is(err, ErrActiveIdentity) {
		t.Fatal("active alias was not rejected before creating the candidate engine")
	}
	if peer.requests.Load() != 0 {
		t.Fatal("rejected alias sent tunnel traffic")
	}
	r.Guard = guardForTest(t, ActiveState{})
	if _, err := Measure(context.Background(), r); !errors.Is(err, ErrUnknownActiveState) {
		t.Fatal("unknown active identity must fail closed")
	}
	if _, err := NewActiveGuard(ActiveState{Known: true, Configuration: "invalid"}); !errors.Is(err, ErrUnknownActiveState) {
		t.Fatal("malformed current identity must fail closed")
	}
}
func TestCancellationReleasesProbePermit(t *testing.T) {
	r, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Measure(ctx, r); err == nil {
		t.Fatal("canceled probe accepted")
	}
	r, _ = fixture(t)
	if _, err := Measure(context.Background(), r); err != nil {
		t.Fatal(err)
	}
}

func TestThirtySequentialProbesReleaseWorkers(t *testing.T) {
	// A warm-up keeps one-time process/runtime initialization out of the count.
	t.Run("warmup", func(t *testing.T) {
		r, _ := fixture(t)
		if _, err := Measure(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	})
	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	baseline := runtime.NumGoroutine()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	peak := before.HeapInuse
	for i := 0; i < 30; i++ {
		t.Run(fmt.Sprintf("candidate-%d", i+1), func(t *testing.T) {
			r, _ := fixture(t)
			if _, err := Measure(context.Background(), r); err != nil {
				t.Fatal(err)
			}
		})
		runtime.ReadMemStats(&after)
		if after.HeapInuse > peak {
			peak = after.HeapInuse
		}
	}
	time.Sleep(100 * time.Millisecond)
	runtime.GC()
	runtime.ReadMemStats(&after)
	if count := runtime.NumGoroutine(); count > baseline+3 {
		t.Fatalf("workers retained: before=%d after=%d", baseline, count)
	}
	t.Logf("30 sequential probes: workers before=%d after=%d; heap in-use before=%d peak=%d after-GC=%d bytes; Windows-only observation", baseline, runtime.NumGoroutine(), before.HeapInuse, peak, after.HeapInuse)
}
