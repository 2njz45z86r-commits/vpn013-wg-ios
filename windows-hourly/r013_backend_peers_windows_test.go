// SPDX-License-Identifier: MIT
// Test-only generated local AWG peers; never part of the client executable.
package tunnel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type nativeDNSPeer struct {
	outbound chan []byte
	events   chan tun.Event
	done     chan struct{}
	once     sync.Once
	delay    time.Duration
	resolve  netip.Addr
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
		if strings.EqualFold(dns.Questions[0].Name.String(), "peer-fixture.invalid.") && dns.Questions[0].Type == dnsmessage.TypeA && p.resolve.Is4() {
			dns.RCode = dnsmessage.RCodeSuccess
			dns.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: dns.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: p.resolve.As4()}}}
		}
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
	p := &nativeDNSPeer{outbound: make(chan []byte, 16), events: make(chan tun.Event, 1), done: make(chan struct{}), delay: delay, resolve: physical}
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
