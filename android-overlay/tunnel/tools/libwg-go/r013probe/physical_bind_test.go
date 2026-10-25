// SPDX-License-Identifier: MIT
package awgprobe

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

type fakePhysicalFactory struct {
	read   func([]byte)
	failed func()
	writer func([]byte, func(error))
	cancel func(func())
	opens  int
}

func (f *fakePhysicalFactory) OpenPhysical(_ netip.AddrPort, read func([]byte), failed func()) (PhysicalUDPSession, error) {
	f.opens++
	f.read, f.failed = read, failed
	return f, nil
}
func (f *fakePhysicalFactory) Write(p []byte, completed func(error)) {
	if f.writer != nil {
		f.writer(p, completed)
	} else {
		completed(nil)
	}
}
func (f *fakePhysicalFactory) Cancel(closed func()) {
	if f.cancel != nil {
		f.cancel(closed)
	} else {
		closed()
	}
}
func fakePhysical(t *testing.T) (*PhysicalBind, *fakePhysicalFactory, conn.ReceiveFunc, conn.Endpoint) {
	t.Helper()
	f := &fakePhysicalFactory{}
	b, err := NewPhysicalBind(netip.MustParseAddrPort("127.0.0.1:12345"), f)
	if err != nil {
		t.Fatal(err)
	}
	fns, _, err := b.Open(0)
	if err != nil || len(fns) != 1 || b.BatchSize() != 1 {
		t.Fatal("batch-one bind unavailable", err)
	}
	t.Cleanup(func() { b.Close() })
	ep, err := b.ParseEndpoint("127.0.0.1:12345")
	if err != nil {
		t.Fatal(err)
	}
	return b, f, fns[0], ep
}

func TestPhysicalQueueIsBoundedBeforeAllocation(t *testing.T) {
	b, f, read, _ := fakePhysical(t)
	packet := bytes.Repeat([]byte{7}, maxProbeDatagram)
	for i := 0; i < 1000; i++ {
		f.read(packet)
	}
	if len(b.state.slots) != probeQueueDepth || len(b.state.packets) != probeQueueDepth {
		t.Fatal("queue not bounded")
	}
	packet[0] = 9
	for i := 0; i < probeQueueDepth; i++ {
		buffer := make([]byte, maxProbeDatagram)
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		if n, err := read([][]byte{buffer}, sizes, eps); n != 1 || err != nil || sizes[0] != len(packet) || buffer[0] != 7 {
			t.Fatal("incorrect or borrowed datagram", n, err)
		}
	}
	f.read(nil)
	f.read(make([]byte, maxProbeDatagram+1))
	if len(b.state.slots) != 0 {
		t.Fatal("invalid datagram queued")
	}
	f.read([]byte{1, 2, 3})
	if _, err := read([][]byte{make([]byte, 1)}, make([]int, 1), make([]conn.Endpoint, 1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
	if len(b.state.slots) != 0 {
		t.Fatal("short receive leaked queue slot")
	}
}

func TestPhysicalWritesWaitForPriorCompletion(t *testing.T) {
	b, f, _, ep := fakePhysical(t)
	started := make(chan func(error), 2)
	var active, max atomic.Int32
	f.writer = func(_ []byte, done func(error)) {
		n := active.Add(1)
		if n > max.Load() {
			max.Store(n)
		}
		started <- func(e error) { active.Add(-1); done(e); done(e) }
	}
	results := make(chan error, 2)
	go func() { results <- b.Send([][]byte{{1}}, ep) }()
	ack := <-started
	go func() { results <- b.Send([][]byte{{2}}, ep) }()
	select {
	case <-started:
		t.Fatal("overlapping platform writes")
	case <-time.After(20 * time.Millisecond):
	}
	ack(nil)
	ack = <-started
	ack(nil)
	if <-results != nil || <-results != nil || max.Load() != 1 {
		t.Fatal("serialization failed")
	}
}

func TestPhysicalPreservesTheWholeAWGHandshakeBurst(t *testing.T) {
	b, f, _, ep := fakePhysical(t)
	var written [][]byte
	f.writer = func(packet []byte, done func(error)) {
		written = append(written, append([]byte(nil), packet...))
		done(nil)
	}
	burst := [][]byte{{1}, {}, {2, 3}, {4, 5, 6}}
	if err := b.Send(burst, ep); err != nil {
		t.Fatal(err)
	}
	if len(written) != len(burst) {
		t.Fatal("handshake burst truncated")
	}
	for i := range burst {
		if !bytes.Equal(written[i], burst[i]) {
			t.Fatal("handshake order/data changed")
		}
	}
}

func TestPhysicalCloseWaitsForActualCancellationAndDiscardsOldEpoch(t *testing.T) {
	b, f, read, ep := fakePhysical(t)
	oldRead := f.read
	closing := make(chan func(), 1)
	f.cancel = func(closed func()) { closing <- closed }
	closed := make(chan error, 1)
	go func() { closed <- b.Close() }()
	ack := <-closing
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatal("reopened while UDP still alive", err)
	}
	if err := b.Send([][]byte{{1}}, ep); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := read([][]byte{make([]byte, 4)}, make([]int, 1), make([]conn.Endpoint, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	select {
	case <-closed:
		t.Fatal("closure acknowledged before platform socket closed")
	default:
	}
	ack()
	ack()
	if <-closed != nil {
		t.Fatal("close failed")
	}
	f.cancel = nil
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	oldRead([]byte{9})
	f.read([]byte{3})
	sizes := make([]int, 1)
	packet := make([]byte, 4)
	if n, err := fns[0]([][]byte{packet}, sizes, make([]conn.Endpoint, 1)); n != 1 || err != nil || packet[0] != 3 {
		t.Fatal("old epoch data admitted", err)
	}
}

func TestPhysicalFailureNeverFallsBackOrAcceptsAnotherPeer(t *testing.T) {
	b, f, _, ep := fakePhysical(t)
	if _, err := b.ParseEndpoint("127.0.0.2:12345"); err == nil {
		t.Fatal("remote roaming accepted")
	}
	other, _ := NewPhysicalBind(b.peer, &fakePhysicalFactory{})
	foreign, _ := other.ParseEndpoint(b.peer.String())
	if err := b.Send([][]byte{{1}}, foreign); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatal(err)
	}
	f.failed()
	if err := b.Send([][]byte{{1}}, ep); !errors.Is(err, net.ErrClosed) || f.opens != 1 {
		t.Fatal("failure created a fallback", err)
	}
	if err := b.SetMark(1); err == nil {
		t.Fatal("pretended to implement SO_MARK")
	}
	if _, err := NewPhysicalBind(b.peer, nil); err == nil {
		t.Fatal("implicit factory accepted")
	}
}

func TestPhysicalMissingWriteCompletionFailsClosed(t *testing.T) {
	b, f, _, ep := fakePhysical(t)
	b.writeTimeout = 20 * time.Millisecond
	var late func(error)
	f.writer = func(_ []byte, done func(error)) { late = done }
	if err := b.Send([][]byte{{1}}, ep); !errors.Is(err, ErrPhysicalTransport) {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{{1}}, ep); !errors.Is(err, net.ErrClosed) {
		t.Fatal("continued after timeout", err)
	}
	late(nil)
}

// This adapter exists ONLY in tests. DialUDP does not prove iOS physical binding.
type loopbackPhysicalFactory struct{}
type loopbackPhysicalSession struct {
	conn     *net.UDPConn
	readDone chan struct{}
	once     sync.Once
}

func (loopbackPhysicalFactory) OpenPhysical(peer netip.AddrPort, read func([]byte), failed func()) (PhysicalUDPSession, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(peer))
	if err != nil {
		return nil, err
	}
	s := &loopbackPhysicalSession{conn: c, readDone: make(chan struct{})}
	go func() {
		defer close(s.readDone)
		buffer := make([]byte, maxProbeDatagram)
		for {
			n, err := c.Read(buffer)
			if err != nil {
				return
			}
			read(buffer[:n])
		}
	}()
	return s, nil
}
func (s *loopbackPhysicalSession) Write(packet []byte, done func(error)) {
	_, err := s.conn.Write(packet)
	done(err)
}
func (s *loopbackPhysicalSession) Cancel(closed func()) {
	s.once.Do(func() { s.conn.Close() })
	<-s.readDone
	closed()
}

func TestPhysicalBatchOneAuthenticatedAWG(t *testing.T) {
	r, peer := fixture(t)
	var endpoint netip.AddrPort
	for _, line := range strings.Split(r.Config, "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			endpoint = netip.MustParseAddrPort(strings.TrimPrefix(line, "endpoint="))
		}
	}
	b, err := NewPhysicalBind(endpoint, loopbackPhysicalFactory{})
	if err != nil {
		t.Fatal(err)
	}
	r.Bind = b
	peer.delay.Store(int64(10 * time.Millisecond))
	result, err := Measure(context.Background(), r)
	if err != nil || result.Samples != 3 || peer.requests.Load() < 4 {
		t.Fatal("bounded transport did not authenticate", result, err)
	}
	t.Logf("Batch1 callback transport: three authenticated samples, median %s; no OS VPN/routes", result.Median)
}
