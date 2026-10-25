// SPDX-License-Identifier: MIT
package r013gate

// This is an isolated native SYSTEM fixture, not production lifecycle wiring.
// Only an ephemeral /32 route/address on a newly created Wintun is modified.
// Peers are local encrypted AWG engines; no customer server or key is used.
import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013tun"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/windows"
)

type nativeDNSPeer struct {
	outbound chan []byte
	events   chan tun.Event
	done     chan struct{}
	once     sync.Once
	delay    time.Duration
	requests atomic.Uint64
}

func (p *nativeDNSPeer) File() *os.File           { return nil }
func (p *nativeDNSPeer) MTU() (int, error)        { return 1420, nil }
func (p *nativeDNSPeer) Name() (string, error)    { return "ephemeral-native-proof-peer", nil }
func (p *nativeDNSPeer) Events() <-chan tun.Event { return p.events }
func (p *nativeDNSPeer) BatchSize() int           { return 1 }
func (p *nativeDNSPeer) Close() error {
	p.once.Do(func() { close(p.done); close(p.events) })
	return nil
}
func (p *nativeDNSPeer) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-p.done:
		return 0, io.EOF
	case packet := <-p.outbound:
		if len(bufs) == 0 || offset+len(packet) > len(bufs[0]) {
			return 0, io.ErrShortBuffer
		}
		copy(bufs[0][offset:], packet)
		sizes[0] = len(packet)
		return 1, nil
	}
}
func nativeChecksum(p []byte) uint16 {
	var sum uint32
	for len(p) > 1 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func (p *nativeDNSPeer) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		if offset < 0 || len(b) < offset+28 {
			continue
		}
		ip := b[offset:]
		if ip[0] != 0x45 || ip[9] != 17 || binary.BigEndian.Uint16(ip[22:24]) != 53 || int(binary.BigEndian.Uint16(ip[2:4])) != len(ip) {
			continue
		}
		var dns dnsmessage.Message
		if dns.Unpack(ip[28:]) != nil || dns.Response || len(dns.Questions) != 1 {
			continue
		}
		dns.Response = true
		dns.RecursionAvailable = true
		dns.RCode = dnsmessage.RCodeNameError
		payload, err := dns.Pack()
		if err != nil {
			continue
		}
		reply := make([]byte, 28+len(payload))
		copy(reply[:28], ip[:28])
		copy(reply[12:16], ip[16:20])
		copy(reply[16:20], ip[12:16])
		copy(reply[20:22], ip[22:24])
		copy(reply[22:24], ip[20:22])
		copy(reply[28:], payload)
		binary.BigEndian.PutUint16(reply[2:4], uint16(len(reply)))
		reply[10], reply[11] = 0, 0
		binary.BigEndian.PutUint16(reply[10:12], nativeChecksum(reply[:20]))
		binary.BigEndian.PutUint16(reply[24:26], uint16(len(payload)+8))
		reply[26], reply[27] = 0, 0
		select {
		case <-p.done:
			return 0, io.EOF
		case <-time.After(p.delay):
		}
		p.requests.Add(1)
		select {
		case p.outbound <- reply:
		case <-p.done:
			return 0, io.EOF
		}
	}
	return len(bufs), nil
}

type nativePeerFixture struct {
	config         string
	endpoint       netip.AddrPort
	source, target netip.Addr
	peer           *nativeDNSPeer
	device         *device.Device
}

func newNativePeer(physical netip.Addr, source netip.Addr, delay time.Duration) (nativePeerFixture, error) {
	var f nativePeerFixture
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return f, err
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return f, err
	}
	p := &nativeDNSPeer{outbound: make(chan []byte, 16), events: make(chan tun.Event, 1), done: make(chan struct{}), delay: delay}
	d := device.NewDevice(p, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	header := "jc=3\njmin=40\njmax=70\ns1=20\ns2=30\nh1=1001\nh2=1002\nh3=1003\nh4=1004\n"
	err = d.IpcSet("private_key=" + hex.EncodeToString(server.Bytes()) + "\nlisten_port=0\n" + header + "public_key=" + hex.EncodeToString(client.PublicKey().Bytes()) + "\nallowed_ip=" + source.String() + "/32\n")
	if err != nil {
		d.Close()
		return f, errors.New("ephemeral server config refused")
	}
	if err = d.Up(); err != nil {
		d.Close()
		return f, err
	}
	state, err := d.IpcGet()
	if err != nil {
		d.Close()
		return f, err
	}
	var port uint64
	for _, line := range strings.Split(state, "\n") {
		if strings.HasPrefix(line, "listen_port=") {
			port, _ = strconv.ParseUint(strings.TrimPrefix(line, "listen_port="), 10, 16)
		}
	}
	if port == 0 {
		d.Close()
		return f, errors.New("ephemeral server port missing")
	}
	endpoint := netip.AddrPortFrom(physical, uint16(port))
	target := netip.MustParseAddr("10.213.99.1")
	return nativePeerFixture{config: "private_key=" + hex.EncodeToString(client.Bytes()) + "\nlisten_port=0\n" + header + "public_key=" + hex.EncodeToString(server.PublicKey().Bytes()) + "\nendpoint=" + endpoint.String() + "\nallowed_ip=" + target.String() + "/32\n", endpoint: endpoint, source: source, target: target, peer: p, device: d}, nil
}

type countedNativeTun struct {
	tun.Device
	closed atomic.Uint32
}

func (t *countedNativeTun) Close() error { t.closed.Add(1); return t.Device.Close() }

type countedPhysical struct {
	probe.PhysicalUDPFactory
	opens atomic.Uint32
}

func (f *countedPhysical) OpenPhysical(p netip.AddrPort, r func([]byte), e func()) (probe.PhysicalUDPSession, error) {
	f.opens.Add(1)
	return f.PhysicalUDPFactory.OpenPhysical(p, r, e)
}

func observeCIPhysical() (uint32, netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return 0, netip.Addr{}, err
	}
	for _, iface := range interfaces {
		if iface.Index <= 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		luid, err := winipcfg.LUIDFromIndex(uint32(iface.Index))
		if err != nil {
			continue
		}
		row, err := luid.Interface()
		if err != nil {
			continue
		}
		if row.Type != winipcfg.IfTypeEthernetCSMACD && row.Type != winipcfg.IfTypeIEEE80211 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, e := netip.ParsePrefix(a.String())
			if e == nil && prefix.Addr().Is4() && !prefix.Addr().IsLinkLocalUnicast() {
				return uint32(iface.Index), prefix.Addr(), nil
			}
		}
	}
	return 0, netip.Addr{}, errors.New("no observed up Ethernet/WiFi CI interface")
}

func nativeStream(ctx context.Context, factory *protectedudp.Factory, target netip.AddrPort, replies *atomic.Uint32) error {
	packets := make(chan []byte, 4)
	session, err := factory.OpenThroughTunnel(target, func(p []byte) {
		select {
		case packets <- append([]byte(nil), p...):
		default:
		}
	}, func() {})
	if err != nil {
		return err
	}
	defer func() { done := make(chan struct{}); session.Cancel(func() { close(done) }); <-done }()
	for ctx.Err() == nil {
		var nonce [8]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		name, _ := dnsmessage.NewName("stream-" + hex.EncodeToString(nonce[:]) + ".invalid.")
		request := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(nonce[:2]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
		wire, _ := request.Pack()
		written := make(chan error, 1)
		session.Write(wire, func(e error) { written <- e })
		if err = <-written; err != nil {
			return err
		}
		select {
		case p := <-packets:
			var reply dnsmessage.Message
			if reply.Unpack(p) != nil || !reply.Response || reply.ID != request.ID || len(reply.Questions) != 1 || reply.Questions[0] != request.Questions[0] {
				return errors.New("foreign native DNS reply")
			}
			replies.Add(1)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
			return errors.New("native stream interrupted")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return ctx.Err()
}

func runNativeWintunProof(ctx context.Context, gate *Gate, nonce string, progress func(string) error) (uint32, uint32, error) {
	index, physical, err := observeCIPhysical()
	if err != nil {
		return 0, 0, err
	}
	primary, err := newNativePeer(physical, netip.MustParseAddr("10.213.99.2"), 25*time.Millisecond)
	if err != nil {
		return 0, 0, err
	}
	defer primary.device.Close()
	candidate, err := newNativePeer(physical, netip.MustParseAddr("10.213.98.2"), time.Millisecond)
	if err != nil {
		return 0, 0, err
	}
	defer candidate.device.Close()
	var tracked *countedNativeTun
	var relay *r013tun.Relay
	var engine *device.Device
	var luid winipcfg.LUID
	var tunnelIndex uint32
	err = gate.Primary(ctx, Stamp{}, func(context.Context) error {
		native, err := tun.CreateTUN("R013Proof-"+nonce[:8], 1420)
		if err != nil {
			return err
		}
		tracked = &countedNativeTun{Device: native}
		relay, err = r013tun.New(tracked)
		if err != nil {
			return err
		}
		lease, err := relay.Open()
		if err != nil {
			return err
		}
		luid = winipcfg.LUID(native.(*tun.NativeTun).LUID())
		binding := conn.NewStdNetBind()
		engine = device.NewDevice(lease, binding, device.NewLogger(device.LogLevelSilent, ""))
		if !engine.SetPrimaryMutationFence(func(work func() error) error {
			return gate.Primary(context.Background(), Stamp{}, func(context.Context) error { return work() })
		}) {
			return errors.New("primary device fence not installed")
		}
		if engine.IpcSet(primary.config) != nil || engine.Up() != nil {
			return errors.New("native primary start failed")
		}
		if err = binding.(conn.BindSocketToInterface).BindSocketToInterface4(index, false); err != nil {
			return err
		}
		iface, err := luid.Interface()
		if err != nil {
			return err
		}
		tunnelIndex = iface.InterfaceIndex
		if tunnelIndex == 0 || tunnelIndex == index {
			return errors.New("native TUN index unavailable")
		}
		ipif, err := luid.IPInterface(windows.AF_INET)
		if err != nil {
			return err
		}
		ipif.NLMTU = 1420
		if err = ipif.Set(); err != nil {
			return err
		}
		if err = luid.AddIPAddress(net.IPNet{IP: net.ParseIP(primary.source.String()).To4(), Mask: net.CIDRMask(32, 32)}); err != nil {
			return err
		}
		destination := net.IPNet{IP: net.ParseIP(primary.target.String()).To4(), Mask: net.CIDRMask(32, 32)}
		if err = luid.AddRoute(destination, net.IPv4zero, 1); err != nil {
			return err
		}
		row, err := luid.Route(destination, net.IPv4zero)
		if err != nil || row.InterfaceIndex != tunnelIndex {
			return errors.New("native /32 route readback differs")
		}
		return nil
	})
	defer gate.Primary(context.Background(), Stamp{}, func(context.Context) error {
		if luid != 0 {
			luid.FlushRoutes(windows.AF_INET)
			luid.FlushIPAddresses(windows.AF_INET)
		}
		if engine != nil {
			engine.Close()
		}
		if relay != nil {
			relay.Close()
		} else if tracked != nil {
			tracked.Close()
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("Wintun native setup: %w", err)
	}
	actual, err := engine.IpcGet()
	if err != nil {
		return 0, 0, err
	}
	guard, err := probe.NewActiveGuard(probe.ActiveState{Known: true, Configuration: actual})
	if err != nil {
		return 0, 0, err
	}
	var before, after uint32
	err = gate.Candidate(ctx, func(work context.Context, token Token) error {
		physicalFactory, err := NewUDPFactory(protectedudp.Physical, index, 0, token)
		if err != nil {
			return err
		}
		defer physicalFactory.Close(context.Background())
		currentFactory, err := NewUDPFactory(protectedudp.ThroughTunnel, tunnelIndex, 0, token)
		if err != nil {
			return err
		}
		defer currentFactory.Close(context.Background())
		target := netip.AddrPortFrom(primary.target, 53)
		// Windows DAD can still be tentative immediately after AddIPAddress; bounded
		// readiness waits use the same through-TUN DNS operation, never a fallback.
		ready := time.Now().Add(8 * time.Second)
		for {
			_, err = probe.MeasureCurrentDNS(work, probe.CurrentDNSRequest{Target: target, Factory: currentFactory, Guard: guard})
			if err == nil {
				break
			}
			if work.Err() != nil || time.Now().After(ready) {
				return fmt.Errorf("native baseline not ready: %w", err)
			}
			time.Sleep(100 * time.Millisecond)
		}
		streamCtx, cancel := context.WithCancel(work)
		streamDone := make(chan error, 1)
		var replies atomic.Uint32
		go func() { streamDone <- nativeStream(streamCtx, currentFactory, target, &replies) }()
		defer func() { cancel(); <-streamDone }()
		start := time.Now().Add(2 * time.Second)
		for replies.Load() == 0 && time.Now().Before(start) {
			time.Sleep(time.Millisecond)
		}
		before = replies.Load()
		if before == 0 {
			return errors.New("native independent stream did not start")
		}
		counted := &countedPhysical{PhysicalUDPFactory: physicalFactory}
		aliasBind, _ := probe.NewPhysicalBind(primary.endpoint, counted)
		otherBind, _ := probe.NewPhysicalBind(candidate.endpoint, counted)
		result, err := probe.Scan(work, probe.ScanRequest{AutoActive: true, Current: probe.CurrentDNSRequest{Target: target, Factory: currentFactory, Guard: guard}, Candidates: []probe.ScanCandidate{
			{ID: "active-alias", DNSRequest: probe.DNSRequest{Request: probe.Request{Config: actual, Source: primary.source, Target: primary.target, Bind: aliasBind, Guard: guard}, Port: 53}},
			{ID: "other-peer", DNSRequest: probe.DNSRequest{Request: probe.Request{Config: candidate.config, Source: candidate.source, Target: candidate.target, Bind: otherBind, Guard: guard}, Port: 53}},
		}})
		after = replies.Load()
		if err != nil {
			return err
		}
		if len(result.Measurements) != 2 || result.Measurements[0].Status != "active_identity_skipped" || result.Measurements[1].Status != "measured" || counted.opens.Load() != 1 {
			return errors.New("native candidate/alias routing proof incomplete")
		}
		if !probe.Comparable(result.Before, result.After) || result.Choice == nil || result.Choice.ID != "other-peer" {
			return errors.New("same-method native ranking not confirmed")
		}
		if after <= before || tracked.closed.Load() != 0 || primary.peer.requests.Load() < 8 || candidate.peer.requests.Load() < 4 {
			return errors.New("native current traffic did not continue during encrypted candidate scan")
		}
		return nil
	})
	if err != nil {
		return before, after, err
	}
	// A fresh backend must not inherit omitted junk/header fields from the
	// preceding profile. Keep the actual same Wintun/route/address, retire the
	// old lease completely, then authenticate a fresh engine with the original
	// immutable synthetic profile. No production switching is claimed here.
	err = gate.Primary(ctx, Stamp{}, func(context.Context) error {
		// Recreate actual upstream WFP sessions after the unchanged privilege
		// drop. Both permissive and restrictive+DNS rules are installed on this
		// disposable runner only. Each dynamic session is closed immediately;
		// a process exit also closes it. No owner firewall/store is touched.
		if err := onlyDriverPrivilegeRemains(); err != nil {
			return err
		}
		if err := progress("before-initial-WFP-close"); err != nil {
			return err
		}
		firewall.DisableFirewall()
		if err := progress("initial-WFP-closed-after-drop"); err != nil {
			return err
		}
		for _, permissive := range []bool{true, false, true} {
			if err := progress(fmt.Sprintf("before-WFP-%t", permissive)); err != nil {
				return err
			}
			if err := firewall.EnableFirewall(uint64(luid), permissive, []net.IP{net.ParseIP(primary.target.String()).To4()}); err != nil {
				return fmt.Errorf("post-drop WFP recreation: %w", err)
			}
			if err := progress(fmt.Sprintf("opened-WFP-%t", permissive)); err != nil {
				firewall.DisableFirewall()
				return err
			}
			firewall.DisableFirewall()
			if err := progress(fmt.Sprintf("closed-WFP-%t", permissive)); err != nil {
				return err
			}
		}
		if err := progress("before-fresh-backend"); err != nil {
			return err
		}
		if err := engine.IpcSet("jc=1\njmin=32\njmax=32\nh1=100\n"); err != nil {
			return err
		}
		engine.Close()
		if tracked.closed.Load() != 0 {
			return errors.New("retired backend closed owned Wintun")
		}
		lease, err := relay.Open()
		if err != nil {
			return err
		}
		binding := conn.NewStdNetBind()
		engine = device.NewDevice(lease, binding, device.NewLogger(device.LogLevelSilent, ""))
		if !engine.SetPrimaryMutationFence(func(work func() error) error {
			return gate.Primary(context.Background(), Stamp{}, func(context.Context) error { return work() })
		}) {
			return errors.New("fresh primary missing lifecycle fence")
		}
		if engine.IpcSet(primary.config) != nil || engine.Up() != nil {
			return errors.New("fresh native backend failed")
		}
		if err = binding.(conn.BindSocketToInterface).BindSocketToInterface4(index, false); err != nil {
			return err
		}
		runtime, err := engine.IpcGet()
		if err != nil {
			return err
		}
		field := func(text, key string) string {
			for _, line := range strings.Split(text, "\n") {
				if value, ok := strings.CutPrefix(line, key+"="); ok {
					return value
				}
			}
			return ""
		}
		// Upstream IpcGet omits zero junk fields. Compare the actual original
		// fresh-engine defaults, rather than requiring a fabricated jc=0 line.
		for _, key := range []string{"jc", "jmin", "jmax", "h1"} {
			if field(runtime, key) != field(actual, key) {
				return errors.New("fresh backend retained preceding obfuscation")
			}
		}
		// Actual watcher ForceMTU and engine MTU reads run concurrently. Native
		// notifications are bounded/coalesced and native close cannot race a send.
		var mtuWork sync.WaitGroup
		mtuWork.Add(1)
		go func() {
			defer mtuWork.Done()
			for i := 0; i < 1000; i++ {
				tracked.Device.(*tun.NativeTun).ForceMTU(1420 + i%2)
			}
		}()
		mtuWork.Wait()
		tracked.Device.(*tun.NativeTun).ForceMTU(1420)
		originalIdentity, err := probe.PublicIdentityDigest(actual)
		if err != nil {
			return err
		}
		freshIdentity, err := probe.PublicIdentityDigest(runtime)
		if err != nil || originalIdentity != freshIdentity {
			return errors.New("fresh engine changed client/server identity")
		}
		row, err := luid.Interface()
		if err != nil || row.InterfaceIndex != tunnelIndex {
			return errors.New("native TUN changed at backend cutover")
		}
		actual = runtime
		return nil
	})
	if err != nil {
		return before, after, err
	}
	if err = progress("fresh-backend-ready"); err != nil {
		return before, after, err
	}
	guard, err = probe.NewActiveGuard(probe.ActiveState{Known: true, Configuration: actual})
	if err != nil {
		return before, after, err
	}
	err = gate.Candidate(ctx, func(work context.Context, token Token) error {
		current, err := NewUDPFactory(protectedudp.ThroughTunnel, tunnelIndex, 0, token)
		if err != nil {
			return err
		}
		defer current.Close(context.Background())
		end := time.Now().Add(5 * time.Second)
		for {
			_, err = probe.MeasureCurrentDNS(work, probe.CurrentDNSRequest{Target: netip.AddrPortFrom(primary.target, 53), Factory: current, Guard: guard})
			if err == nil {
				return nil
			}
			if work.Err() != nil || time.Now().After(end) {
				return fmt.Errorf("same TUN fresh backend DNS: %w", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
	return before, after, err
}
