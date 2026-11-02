package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// Uses synthetic loopback peers. The datagram has a plausible session index
// and overlapping response/transport types, but no valid transport AEAD tag.
func TestVPN013QueuedCandidateRejectsForgedTraffic(t *testing.T) {
	for _, protected := range []bool{false, true} {
		t.Run(fmt.Sprintf("header-protection-%t", protected), func(t *testing.T) {
			options := []string{"s1", "97", "s2", "41", "s3", "133", "s4", "24",
				"h1", "305419896-405419895", "h2", "1122334455-1222334454",
				"h3", "1987654321-2087654320", "h4", "3000000000-3099999999",
				"random_trailers", "true", "content_padding_addition", "200"}
			if protected {
				options = append(options, "header_protection_key", "d7068cea352177b603b321c845694f89c8174b47f926a5c59bd2a72065675736")
			}
			pair := genTestPair(t, true, options...)
			pair.Send(t, Ping, nil)
			receiver := pair[0].dev
			receiver.peers.RLock()
			var kp *Keypair
			for _, peer := range receiver.peers.keyMap {
				kp = peer.keypairs.Current()
				break
			}
			receiver.peers.RUnlock()
			if kp == nil {
				t.Fatal("missing synthetic live session")
			}
			packet := make([]byte, 200)
			for i := 0; i < HeaderCipherNonceSize; i++ {
				packet[i] = byte(i + 1)
			}
			offset := 24
			binary.LittleEndian.PutUint32(packet[offset:], 3000001234)
			binary.LittleEndian.PutUint32(packet[offset+4:], kp.localIndex)
			binary.LittleEndian.PutUint64(packet[offset+8:], 123456)
			hash := make([]byte, 4)
			cipher, err := receiver.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
			if err != nil {
				t.Fatal(err)
			}
			if cipher != nil {
				cipher.XORKeyStream(packet[offset:offset+MessageTransportHeaderSize], packet[offset:offset+MessageTransportHeaderSize])
				c, err := receiver.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
				if err != nil {
					t.Fatal(err)
				}
				c.XORKeyStream(hash, hash)
			}
			binary.LittleEndian.PutUint32(packet[41:], 1122334455^binary.LittleEndian.Uint32(hash))
			_, kind, _ := receiver.DeterminePacketTypeAndPadding(packet, hash)
			if kind != MessageResponseType {
				t.Fatalf("expected original control collision, got %d", kind)
			}
			if _, ok := receiver.vpn013TransportCandidate(packet, hash); !ok {
				t.Fatal("candidate not recognized")
			}
			if _, _, _, ok := receiver.vpn013AuthenticatedControl(packet, hash, true); ok {
				t.Fatal("forged control validated")
			}
			addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(receiver.net.port)}
			sock, err := net.DialUDP("udp4", nil, addr)
			if err != nil {
				t.Fatal(err)
			}
			defer sock.Close()
			if _, err = sock.Write(packet); err != nil {
				t.Fatal(err)
			}
			select {
			case <-pair[0].tun.Inbound:
				t.Fatal("forged transport reached TUN")
			case <-time.After(150 * time.Millisecond):
			}
			// The forged frame must not consume replay state or disturb real traffic.
			expected := tuntest.Ping(pair[0].ip, pair[1].ip)
			pair[1].tun.Outbound <- expected
			select {
			case got := <-pair[0].tun.Inbound:
				if !bytes.Equal(got, expected) {
					t.Fatal("real packet changed")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("real packet lost after forgery")
			}
		})
	}
}
