// SPDX-License-Identifier: MIT
// Experimental memory-only ICMP probe. Not integrated in a shipped client.
package awgprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// Caller must supply a fresh physical-network bind. No unprotected fallback is
// provided: iOS/Android/Windows routing remains a separate, unverified boundary.
type Request struct {
	Config         string
	Source, Target netip.Addr
	Bind           conn.Bind
	Guard          *ActiveGuard
}

type Result struct {
	Median  time.Duration
	Samples int
	Epoch   uint64
	Method  string
	Target  netip.AddrPort
}

var permit = make(chan struct{}, 1)

// Measure has one in-flight probe process-wide, one memory-only interface, no
// filesystem, OS VPN, route or DNS changes. It uses existing keys only in memory.
func Measure(parent context.Context, r Request) (Result, error) {
	return measureCandidate(parent, r, func() (samplingTun, error) {
		return newMemory(r.Source, r.Target), nil
	}, "icmp-echo-v1", netip.AddrPortFrom(r.Target, 0))
}

type samplingTun interface {
	tun.Device
	sample(context.Context) (time.Duration, error)
}

func measureCandidate(parent context.Context, r Request, create func() (samplingTun, error), method string, target netip.AddrPort) (Result, error) {
	var result Result
	if r.Guard == nil {
		return result, ErrUnknownActiveState
	}
	if r.Bind == nil || r.Config == "" || !r.Source.Is4() || !r.Target.Is4() {
		return result, errors.New("explicit bind, IPv4 source/target and configuration required")
	}
	if err := validateProbeResources(r.Config); err != nil {
		return result, err
	}
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	select {
	case permit <- struct{}{}:
		defer func() { <-permit }()
	case <-ctx.Done():
		return result, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	ctx, lease, err := r.Guard.acquire(ctx, r.Config)
	if err != nil {
		return result, err
	}
	// Registered before creating a device; released AFTER dev.Close below.
	defer lease.release()
	memory, err := create()
	if err != nil {
		return result, err
	}
	dev := device.NewDevice(memory, r.Bind, device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(r.Config); err != nil {
		return result, errors.New("probe configuration rejected")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := dev.Up(); err != nil {
		return result, errors.New("probe transport unavailable")
	}
	return collectSamples(ctx, memory.sample, lease.epoch, method, target, r.Guard)
}

// Both candidate and active-path DNS use this exact warmup/three-sample policy.
func collectSamples(ctx context.Context, sample func(context.Context) (time.Duration, error), epoch uint64, method string, target netip.AddrPort, guard *ActiveGuard) (Result, error) {
	if _, err := sample(ctx); err != nil {
		return Result{}, err
	}
	values := make([]time.Duration, 0, 3)
	for i := 0; i < 3; i++ {
		value, err := sample(ctx)
		if err != nil {
			return Result{}, err
		}
		values = append(values, value)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	result := Result{Median: values[1], Samples: len(values), Epoch: epoch, Method: method, Target: target}
	if !guard.Accept(result) {
		return Result{}, ErrStaleEpoch
	}
	return result, nil
}

// Comparable prevents ranking different methods, destinations or active epochs.
func Comparable(a, b Result) bool {
	return a.Method != "" && a.Method == b.Method && a.Target.IsValid() && a.Target == b.Target &&
		a.Epoch != 0 && a.Epoch == b.Epoch && a.Samples == 3 && b.Samples == 3 && a.Median >= 0 && b.Median >= 0
}

type memoryTun struct {
	source, target netip.Addr
	outbound       chan []byte
	inbound        chan []byte
	events         chan tun.Event
	done           chan struct{}
	once           sync.Once
}

func newMemory(source, target netip.Addr) *memoryTun {
	return &memoryTun{source: source, target: target, outbound: make(chan []byte, 4), inbound: make(chan []byte, 4), events: make(chan tun.Event, 1), done: make(chan struct{})}
}
func (*memoryTun) File() *os.File             { return nil }
func (*memoryTun) Name() (string, error)      { return "r013-memory-probe", nil }
func (*memoryTun) MTU() (int, error)          { return 1420, nil }
func (*memoryTun) BatchSize() int             { return 1 }
func (m *memoryTun) Events() <-chan tun.Event { return m.events }
func (m *memoryTun) Close() error             { m.once.Do(func() { close(m.done); close(m.events) }); return nil }
func (m *memoryTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-m.done:
		return 0, io.EOF
	case p := <-m.outbound:
		if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset+len(p) > len(bufs[0]) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], p)
		sizes[0] = len(p)
		return 1, nil
	}
}
func (m *memoryTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if offset < 0 || offset > len(b) {
			return 0, io.ErrShortBuffer
		}
		p := b[offset:]
		if len(p) != 44 || p[0] != 0x45 || p[9] != 1 || p[20] != 0 || p[21] != 0 || binary.BigEndian.Uint16(p[2:4]) != uint16(len(p)) || checksum(p[:20]) != 0 || checksum(p[20:]) != 0 {
			continue
		}
		src := m.target.As4()
		dst := m.source.As4()
		if string(p[12:16]) != string(src[:]) || string(p[16:20]) != string(dst[:]) {
			continue
		}
		select {
		case m.inbound <- append([]byte(nil), p...):
		case <-m.done:
			return 0, io.EOF
		default:
		}
	}
	return len(bufs), nil
}
func (m *memoryTun) echo(ctx context.Context) (time.Duration, error) {
	p := make([]byte, 44)
	p[0] = 0x45
	p[8] = 64
	p[9] = 1
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	source := m.source.As4()
	target := m.target.As4()
	copy(p[12:16], source[:])
	copy(p[16:20], target[:])
	p[20] = 8
	if _, err := rand.Read(p[24:]); err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[22:24], checksum(p[20:]))
	start := time.Now()
	retry := time.NewTicker(time.Second)
	defer retry.Stop()
	send := func() error {
		select {
		case m.outbound <- p:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-m.done:
			return io.EOF
		}
	}
	if err := send(); err != nil {
		return 0, err
	}
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-m.done:
			return 0, io.EOF
		case <-retry.C:
			if err := send(); err != nil {
				return 0, err
			}
		case reply := <-m.inbound:
			if string(reply[24:]) == string(p[24:]) {
				return time.Since(start), nil
			}
		}
	}
}

func (m *memoryTun) sample(ctx context.Context) (time.Duration, error) { return m.echo(ctx) }
func checksum(p []byte) uint16 {
	var s uint32
	for len(p) > 1 {
		s += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) == 1 {
		s += uint32(p[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
