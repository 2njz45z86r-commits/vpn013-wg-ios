// SPDX-License-Identifier: MIT
package r013tun

import (
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type fakeTun struct {
	packets      chan []byte
	entered      chan struct{}
	events       chan tun.Event
	done         chan struct{}
	once         sync.Once
	closed       atomic.Uint32
	writeStarted chan struct{}
	writeRelease chan struct{}
	writeCalls   atomic.Uint32
	batch        int
}

func newFake() *fakeTun {
	return &fakeTun{packets: make(chan []byte, 16), entered: make(chan struct{}, 64), events: make(chan tun.Event, 8), done: make(chan struct{}), batch: 1}
}
func (f *fakeTun) Read(b [][]byte, s []int, o int) (int, error) {
	select {
	case f.entered <- struct{}{}:
	case <-f.done:
		return 0, os.ErrClosed
	}
	select {
	case p := <-f.packets:
		s[0] = copy(b[0][o:], p)
		return 1, nil
	case <-f.done:
		return 0, os.ErrClosed
	}
}
func (f *fakeTun) Write(b [][]byte, o int) (int, error) {
	f.writeCalls.Add(1)
	if f.writeStarted != nil {
		f.writeStarted <- struct{}{}
		select {
		case <-f.writeRelease:
		case <-f.done:
			return 0, os.ErrClosed
		}
	}
	return len(b), nil
}
func (f *fakeTun) Close() error {
	f.once.Do(func() { f.closed.Add(1); close(f.done); close(f.events) })
	return nil
}
func (f *fakeTun) File() *os.File           { return nil }
func (f *fakeTun) Name() (string, error)    { return "isolated-fixture", nil }
func (f *fakeTun) MTU() (int, error)        { return 1420, nil }
func (f *fakeTun) Events() <-chan tun.Event { return f.events }
func (f *fakeTun) BatchSize() int           { return f.batch }
func wait(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded wait expired")
	}
}
func readPacket(l *Lease) (string, error) {
	b := make([]byte, 128)
	s := make([]int, 1)
	_, e := l.Read([][]byte{b}, s, 0)
	return string(b[:s[0]]), e
}

func TestExclusiveTUNLeasesNeverCloseNativeOrDeliverOldGeneration(t *testing.T) {
	f := newFake()
	r, e := New(f)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	wait(t, f.entered) // first raw read captures no lease.
	old, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Open(); e == nil {
		t.Fatal("overlapping lease accepted")
	}
	f.packets <- []byte("unowned")
	wait(t, f.entered)
	f.packets <- []byte("old")
	wait(t, f.entered)
	if p, e := readPacket(old); e != nil || p != "old" {
		t.Fatalf("old read %q %v", p, e)
	}
	if e = old.Close(); e != nil || f.closed.Load() != 0 {
		t.Fatal("lease closed native")
	}
	fresh, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	f.packets <- []byte("captured-before-cutover")
	wait(t, f.entered)
	f.packets <- []byte("fresh")
	wait(t, f.entered)
	if p, e := readPacket(fresh); e != nil || p != "fresh" {
		t.Fatalf("stale generation %q %v", p, e)
	}
	if _, e = old.Write([][]byte{[]byte("old")}, 0); e == nil || f.writeCalls.Load() != 0 {
		t.Fatal("closed lease wrote")
	}
	if _, e = readPacket(old); e == nil {
		t.Fatal("closed lease read")
	}
}

func TestTUNLeaseCloseWaitsForRealWriteAndBlocksSuccessor(t *testing.T) {
	f := newFake()
	f.writeStarted = make(chan struct{}, 1)
	f.writeRelease = make(chan struct{})
	r, _ := New(f)
	defer r.Close()
	l, _ := r.Open()
	written := make(chan struct{})
	go func() {
		defer close(written)
		if _, e := l.Write([][]byte{[]byte("fixture")}, 0); e != nil {
			t.Error(e)
		}
	}()
	wait(t, f.writeStarted)
	closed := make(chan struct{})
	go func() { l.Close(); close(closed) }()
	deadline := time.Now().Add(time.Second)
	for {
		r.mu.Lock()
		done := l.closed
		r.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("close did not begin")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-closed:
		t.Fatal("fake close acknowledgement")
	default:
	}
	if _, e := r.Open(); e == nil {
		t.Fatal("successor overlapped old IO")
	}
	close(f.writeRelease)
	wait(t, written)
	wait(t, closed)
	next, e := r.Open()
	if e != nil {
		t.Fatal(e)
	}
	next.Close()
	if f.closed.Load() != 0 {
		t.Fatal("native closed between engines")
	}
}

func TestTUNRelayBoundsQueueAndValidatesBatchAndBuffers(t *testing.T) {
	f := newFake()
	f.batch = 128
	if _, e := New(f); e == nil || f.closed.Load() != 0 {
		t.Fatal("non-batch-one accepted or caller ownership stolen")
	}
	f.batch = 1
	r, _ := New(f)
	defer r.Close()
	wait(t, f.entered)
	l, _ := r.Open()
	defer l.Close()
	f.packets <- []byte("warmup")
	wait(t, f.entered)
	for i := 0; i < 20; i++ {
		f.packets <- []byte("packet")
		wait(t, f.entered)
	}
	r.mu.Lock()
	queued := len(l.packets)
	r.mu.Unlock()
	if queued != queuePackets {
		t.Fatalf("queue %d", queued)
	}
	if _, e := l.Read([][]byte{make([]byte, 1)}, make([]int, 1), 0); e != io.ErrShortBuffer {
		t.Fatal("truncation accepted")
	}
	if _, e := l.Write([][]byte{[]byte("x")}, 2); e != io.ErrShortBuffer {
		t.Fatal("bad offset accepted")
	}
	f.events <- tun.EventMTUUpdate
	select {
	case e := <-l.Events():
		if e != tun.EventMTUUpdate {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("MTU event lost")
	}
}

func TestTUNRelayNativeFailureUnblocksLeaseAndCloseDrainsWorkers(t *testing.T) {
	f := newFake()
	r, _ := New(f)
	l, _ := r.Open()
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		if _, e := readPacket(l); e == nil {
			t.Error("native failure hidden")
		}
	}()
	f.Close()
	wait(t, readDone)
	if _, e := r.Open(); e == nil {
		t.Fatal("failed native device reused")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	r.Close()
	l.Close()
	if f.closed.Load() != 1 {
		t.Fatal("native closed more than once")
	}
}
