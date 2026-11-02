package device

import (
	"bytes"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestVPN013MoveTUNPayloadBounds(t *testing.T) {
	for _, test := range []struct {
		name           string
		old, new, size int
		valid          bool
	}{
		{"unchanged", 4, 4, 8, true}, {"overlap-forward", 4, 8, 8, true},
		{"overlap-backward", 8, 4, 8, true}, {"source-out-of-range", 12, 4, 8, false},
		{"destination-out-of-range", 4, 12, 8, false}, {"negative-size", 4, 4, -1, false},
		{"negative-source", -1, 4, 1, false}, {"negative-destination", 4, -1, 1, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			buf := []byte("0123456789abcdef")
			before := append([]byte(nil), buf...)
			var payload []byte
			if test.valid {
				payload = append([]byte(nil), buf[test.old:test.old+test.size]...)
			}
			if got := r013MoveTUNPayload(buf, test.size, test.old, test.new); got != test.valid {
				t.Fatalf("valid=%v, got=%v", test.valid, got)
			}
			if !test.valid && !bytes.Equal(buf, before) {
				t.Fatal("invalid move mutated buffer")
			}
			if test.valid && !bytes.Equal(buf[test.new:test.new+test.size], payload) {
				t.Fatal("payload changed")
			}
		})
	}
}

type vpn013ObservedTun struct {
	tun.Device
	started chan int
	once    sync.Once
}

func (t *vpn013ObservedTun) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	t.once.Do(func() { t.started <- offset })
	return t.Device.Read(packets, sizes, offset)
}

func TestVPN013S4BlockedReadReposition(t *testing.T) {
	classic := []string{"jc", "4", "jmin", "40", "jmax", "70", "s1", "16", "s2", "16", "h1", "1", "h2", "2", "h3", "3", "h4", "4"}
	v2 := append(append([]string{}, classic...), "s3", "16", "s4", "16", "i1", "<b 0x00>", "i2", "<r 4>", "i3", "<b 0x01>", "i4", "<r 8>", "i5", "<b 0x02>")
	v31 := append(append([]string{}, v2...), "header_protection_key", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", "content_padding_addition", "0", "random_trailers", "false")
	v31WithTrailers := append(append([]string{}, v31...), "random_trailers", "true")
	for _, scenario := range []struct {
		name    string
		options []string
	}{
		{"wireguard", nil}, {"amnezia-classic", classic}, {"amnezia-2", v2}, {"amnezia-3.1", v31}, {"amnezia-3.1-trailers", v31WithTrailers},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			configs, endpoints := genConfigs(t, scenario.options...)
			var pair testPair
			for i := range pair {
				pair[i].tun = tuntest.NewChannelTUN()
				pair[i].ip = netip.AddrFrom4([4]byte{1, 0, 0, byte(i + 1)})
				watched := &vpn013ObservedTun{Device: pair[i].tun.TUN(), started: make(chan int, 1)}
				pair[i].dev = NewDevice(watched, conn.NewDefaultBind(), NewLogger(LogLevelError, "test: "))
				t.Cleanup(pair[i].dev.Close)
				select {
				case offset := <-watched.started:
					if offset != MessageTransportHeaderSize {
						t.Fatalf("unexpected initial offset: %d", offset)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("TUN read did not start")
				}
				if err := pair[i].dev.IpcSet(configs[i]); err != nil {
					t.Fatal(err)
				}
				if err := pair[i].dev.Up(); err != nil {
					t.Fatal(err)
				}
				endpoints[i^1] = fmt.Sprintf(endpoints[i^1], pair[i].dev.net.port)
			}
			for i := range pair {
				if err := pair[i].dev.IpcSet(endpoints[i]); err != nil {
					t.Fatal(err)
				}
			}
			pair.Send(t, Ping, nil)
			pair.Send(t, Pong, nil)
		})
	}
}
