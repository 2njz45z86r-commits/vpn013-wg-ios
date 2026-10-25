// SPDX-License-Identifier: MIT
package r013gate

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func requireCI(t *testing.T) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" {
		t.Fatal("Disposable authorized Windows CI required; no local native execution")
	}
}
func testName(t *testing.T) string {
	t.Helper()
	requireCI(t)
	var b [12]byte
	if _, e := rand.Read(b[:]); e != nil {
		t.Fatal(e)
	}
	return `Local\VPN013-Probe-CI-` + hex.EncodeToString(b[:])
}
func testGate(t *testing.T, name string) *Gate {
	t.Helper()
	g, e := openNamed(name)
	if e != nil {
		t.Fatalf("Open barrier: %v", e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if e := g.Close(ctx); e != nil {
			t.Errorf("Drain barrier: %v", e)
		}
	})
	return g
}
func receive(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case s := <-ch:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("Child handshake timed out")
		return ""
	}
}
func child(t *testing.T, name, mode string) (*exec.Cmd, <-chan string) {
	t.Helper()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestGateChild$")
	cmd.Env = append(os.Environ(), "R013_GATE_CHILD="+mode, "R013_GATE_NAME="+name)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = os.Stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	lines := make(chan string, 8)
	go func() {
		defer close(lines)
		s := bufio.NewScanner(pipe)
		for s.Scan() {
			if strings.HasPrefix(s.Text(), "R013:") {
				lines <- strings.TrimPrefix(s.Text(), "R013:")
			}
		}
	}()
	return cmd, lines
}

func TestGateChild(t *testing.T) {
	mode := os.Getenv("R013_GATE_CHILD")
	if mode == "" {
		return
	}
	requireCI(t)
	name := os.Getenv("R013_GATE_NAME")
	if !strings.HasPrefix(name, `Local\VPN013-Probe-CI-`) {
		t.Fatal("Invalid test namespace")
	}
	g, e := openNamed(name)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close(context.Background())
	switch mode {
	case "primary":
		e = g.Primary(context.Background(), Stamp{}, func(context.Context) error { fmt.Println("R013:MUTATING"); return nil })
	case "abandon":
		e = g.Candidate(context.Background(), func(context.Context, Token) error {
			udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				return e
			}
			fmt.Println("R013:READY " + udp.LocalAddr().String())
			os.Exit(17)
			return nil
		})
	default:
		t.Fatal("Unknown child operation")
	}
	if e != nil {
		t.Fatal(e)
	}
}

func TestCrossProcessRequestCancelsAndWaitsForActualUDPClosure(t *testing.T) {
	name := testName(t)
	g := testGate(t, name)
	ready := make(chan struct{})
	cancelled := make(chan struct{})
	ack := make(chan struct{})
	done := make(chan error, 1)
	var once sync.Once
	defer once.Do(func() { close(ack) })
	var closed atomic.Bool
	go func() {
		done <- g.Candidate(context.Background(), func(ctx context.Context, token Token) error {
			udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				return e
			}
			defer udp.Close()
			close(ready)
			<-ctx.Done()
			if token.Valid() {
				return errors.New("stale token accepted")
			}
			close(cancelled)
			<-ack
			if e = udp.Close(); e != nil {
				return e
			}
			closed.Store(true)
			return nil
		})
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("Candidate did not start")
	}
	cmd, lines := child(t, name, "primary")
	select {
	case <-cancelled:
	case <-time.After(3 * time.Second):
		t.Fatal("Cross-process request did not cancel")
	}
	select {
	case line := <-lines:
		t.Fatalf("Primary entered before close ACK: %s", line)
	case <-time.After(150 * time.Millisecond):
	}
	once.Do(func() { close(ack) })
	if s := receive(t, lines); s != "MUTATING" {
		t.Fatalf("Unexpected child result: %s", s)
	}
	if !closed.Load() {
		t.Fatal("Primary acquired before actual descriptor closure")
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := cmd.Wait(); e != nil {
		t.Fatal(e)
	}
}

func TestExpectedStampIsOneShotAndMappingLifetimeCannotABA(t *testing.T) {
	name := testName(t)
	g := testGate(t, name)
	stamp := g.Current()
	count := 0
	if e := g.Primary(context.Background(), stamp, func(context.Context) error { count++; return nil }); e != nil {
		t.Fatal(e)
	}
	if e := g.Primary(context.Background(), stamp, func(context.Context) error { count++; return nil }); !errors.Is(e, ErrStale) {
		t.Fatalf("Replayed stamp: %v", e)
	}
	if count != 1 {
		t.Fatal("Replayed mutation ran")
	}
	if e := g.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	newGate := testGate(t, name)
	if newGate.Current().Instance == stamp.Instance {
		t.Fatal("Mapping instance reused")
	}
	if e := newGate.Primary(context.Background(), stamp, func(context.Context) error { count++; return nil }); !errors.Is(e, ErrStale) {
		t.Fatalf("Old mapping stamp accepted: %v", e)
	}
	if (Token{}).Valid() {
		t.Fatal("Zero token accepted")
	}
}

func TestDeadProcessClosesSocketAndAbandonedCandidateIsRefused(t *testing.T) {
	name := testName(t)
	g := testGate(t, name)
	cmd, lines := child(t, name, "abandon")
	address := strings.TrimPrefix(receive(t, lines), "READY ")
	var exit *exec.ExitError
	if e := cmd.Wait(); !errors.As(e, &exit) || exit.ExitCode() != 17 {
		t.Fatalf("Expected process death, got %v", e)
	}
	addr, e := net.ResolveUDPAddr("udp4", address)
	if e != nil {
		t.Fatal(e)
	}
	socket, e := net.ListenUDP("udp4", addr)
	if e != nil {
		t.Fatalf("Dead-process socket remained open: %v", e)
	}
	socket.Close()
	called := false
	e = g.Candidate(context.Background(), func(context.Context, Token) error { called = true; return nil })
	if !errors.Is(e, ErrAbandoned) || called {
		t.Fatalf("Abandoned identity trusted: %v", e)
	}
	if e = g.Primary(context.Background(), Stamp{}, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
}

func TestCloseTimeoutRetainsOwnedBarrierUntilRealDrain(t *testing.T) {
	name := testName(t)
	g := testGate(t, name)
	peer := testGate(t, name)
	ready := make(chan struct{})
	ack := make(chan struct{})
	done := make(chan error, 1)
	var once sync.Once
	defer once.Do(func() { close(ack) })
	go func() {
		done <- g.Candidate(context.Background(), func(ctx context.Context, token Token) error { close(ready); <-ctx.Done(); <-ack; return nil })
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("Candidate not ready")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if e := g.Close(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("Close faked completion: %v", e)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel2()
	called := false
	if e := peer.Primary(ctx2, Stamp{}, func(context.Context) error { called = true; return nil }); e == nil || called {
		t.Fatal("Timeout released live barrier")
	}
	once.Do(func() { close(ack) })
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if e := g.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := peer.Primary(context.Background(), Stamp{}, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
}

func TestExistingBroadenedKernelACLIsRejected(t *testing.T) {
	name := testName(t)
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	if e != nil {
		t.Fatal(e)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	ptr, _ := windows.UTF16PtrFromString(name + "-mutex")
	h, e := windows.CreateMutex(&sa, false, ptr)
	if e != nil {
		t.Fatal(e)
	}
	defer windows.CloseHandle(h)
	if g, e := openNamed(name); !errors.Is(e, ErrUnavailable) || g != nil {
		t.Fatal("World-writable existing barrier was accepted")
	}
}
