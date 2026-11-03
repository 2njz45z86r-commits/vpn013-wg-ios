package wireguard

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"github.com/xtls/xray-core/common/log"
)

type vpn013LogCollector struct {
	mu    sync.Mutex
	lines []string
}

func (c *vpn013LogCollector) Handle(m log.Message) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, m.String())
}

func TestVPN013AWGInvalidValueNotLogged(t *testing.T) {
	collector := &vpn013LogCollector{}
	log.RegisterHandler(collector)
	t.Cleanup(func() { log.RegisterHandler(&vpn013LogCollector{}) })
	fixture := tuntest.NewChannelTUN()
	tunnel := &vpn013CountedTUN{Device: fixture.TUN(), events: make(chan tun.Event)}
	marker := "SYNTHETIC_SECRET_736128"
	h := &Handler{tun: tunnel, conf: &DeviceConfig{Vpn013Awg: map[string]string{"random_trailers": marker}}}
	if h.init(context.Background()) == nil {
		t.Fatal("invalid flag accepted")
	}
	collector.mu.Lock()
	defer collector.mu.Unlock()
	for _, line := range collector.lines {
		if strings.Contains(line, marker) {
			t.Fatal("synthetic private marker appeared in backend log")
		}
	}
}

type vpn013CountedTUN struct {
	tun.Device
	closes atomic.Int32
	events chan tun.Event
}

func (v *vpn013CountedTUN) Events() <-chan tun.Event { return v.events }
func (v *vpn013CountedTUN) Close() error             { v.closes.Add(1); close(v.events); return v.Device.Close() }

func TestVPN013AWGSemanticFailureClosesTUN(t *testing.T) {
	fixture := tuntest.NewChannelTUN()
	tunnel := &vpn013CountedTUN{Device: fixture.TUN(), events: make(chan tun.Event, 1)}
	tunnel.events <- tun.EventUp
	h := &Handler{tun: tunnel, conf: &DeviceConfig{Vpn013Awg: map[string]string{"s1": "not-a-number"}}}
	err := h.init(context.Background())
	if err == nil || strings.Contains(err.Error(), "not-a-number") {
		t.Fatal("must reject invalid parameter without echoing its value")
	}
	if tunnel.closes.Load() != 1 || h.tun != nil || h.dev != nil {
		t.Fatal("failed initialization did not close and detach TUN exactly once")
	}
	if h.init(context.Background()) == nil {
		t.Fatal("closed failed instance cannot be silently reused")
	}
	if err := h.Close(); err != nil || tunnel.closes.Load() != 1 {
		t.Fatal("close was not idempotent")
	}
}

func TestVPN013TUNEventsWaitForConfiguration(t *testing.T) {
	fixture := tuntest.NewChannelTUN()
	underlying := &vpn013CountedTUN{Device: fixture.TUN(), events: make(chan tun.Event, 1)}
	underlying.events <- tun.EventUp
	gate := newVPN013GatedTUN(underlying)
	select {
	case <-gate.Events():
		t.Fatal("event escaped before configuration")
	case <-time.After(25 * time.Millisecond):
	}
	gate.enableEvents()
	select {
	case event := <-gate.Events():
		if event != tun.EventUp {
			t.Fatal("wrong event")
		}
	case <-time.After(time.Second):
		t.Fatal("event not released")
	}
	if err := gate.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-gate.Events():
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(time.Second):
		t.Fatal("event channel not closed")
	}
	if err := gate.Close(); err != nil || underlying.closes.Load() != 1 {
		t.Fatal("close was not idempotent")
	}
}

func TestVPN013AWGAllowedOrdered(t *testing.T) {
	got, err := VPN013AWGLines(map[string]string{"s4": "20", "i1": "<b 0x1234><r 16>", "r013_legacy15": "true", "h1": "123-456"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"r013_legacy15=true\n", "h1=123-456\n", "i1=<b 0x1234><r 16>\n", "s4=20\n"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("line %d differs", i)
		}
	}
}

func TestVPN013AWGRejectsInjectionAndUnbounded(t *testing.T) {
	cases := []map[string]string{
		{"private_key": "synthetic-secret"}, {"i1": "ok\nprivate_key=evil"}, {"i1": "ok\rpublic_key=evil"},
		{"i1": "x\x00y"}, {"h1": "evil=value"}, {"i1": strings.Repeat("x", 16385)},
		{"r013_legacy15": "yes"}, {"i1": "\u0401"},
	}
	for i, fields := range cases {
		got, err := VPN013AWGLines(fields)
		if err == nil || got != nil {
			t.Fatalf("case %d was not rejected", i)
		}
		if strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), "evil") {
			t.Fatalf("case %d leaked input", i)
		}
	}
}

func TestVPN013AWGTotalBudgetAndEmptyWireGuard(t *testing.T) {
	if got, err := VPN013AWGLines(nil); err != nil || len(got) != 0 {
		t.Fatal("plain WireGuard must remain unchanged")
	}
	values := map[string]string{}
	for _, key := range []string{"i1", "i2", "i3", "i4", "i5", "j1", "j2"} {
		values[key] = strings.Repeat("x", 16384)
	}
	if _, err := VPN013AWGLines(values); err == nil {
		t.Fatal("aggregate limit not enforced")
	}
}
