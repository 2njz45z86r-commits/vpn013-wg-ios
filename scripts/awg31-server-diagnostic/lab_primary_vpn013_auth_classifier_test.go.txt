package device

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"golang.org/x/crypto/chacha20poly1305"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVPN013AuthenticatedTransportFallback(t *testing.T) {
	dir := os.Getenv("AWG_FIXTURES")
	if dir == "" {
		t.Fatal("synthetic fixture path is required")
	}
	var p struct {
		S            map[string]uint32    `json:"s"`
		H            map[string][2]uint32 `json:"h"`
		RT           bool                 `json:"random_trailers"`
		HP           string               `json:"hp_key_hex"`
		TransportKey string               `json:"transport_key_hex"`
		Index        uint32               `json:"receiver_index"`
	}
	raw, err := os.ReadFile(filepath.Join(dir, "params.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	d := new(Device)
	d.paddings.init.Store(p.S["initiation"])
	d.paddings.response.Store(p.S["response"])
	d.paddings.cookie.Store(p.S["cookie_reply"])
	d.paddings.transport.Store(p.S["transport"])
	var r UintRange
	r.FromUint32(p.H["initiation"][0], p.H["initiation"][1])
	d.headers.init.Store(r)
	r.FromUint32(p.H["response"][0], p.H["response"][1])
	d.headers.response.Store(r)
	r.FromUint32(p.H["cookie_reply"][0], p.H["cookie_reply"][1])
	d.headers.cookie.Store(r)
	r.FromUint32(p.H["transport"][0], p.H["transport"][1])
	d.headers.transport.Store(r)
	d.randomTrailers.Store(p.RT)
	hp, err := hex.DecodeString(p.HP)
	if err != nil {
		t.Fatal(err)
	}
	copy(d.headerProtection.key[:], hp)
	key, err := hex.DecodeString(p.TransportKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	d.indexTable.Init()
	d.indexTable.table[p.Index] = IndexTableEntry{peer: &Peer{}, keypair: &Keypair{receive: aead, created: time.Now()}}
	for _, name := range []string{"ambiguous-transport.bin", "redrawn-transport.bin"} {
		t.Run(name, func(t *testing.T) {
			packet, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			before := append([]byte(nil), packet...)
			cip, err := d.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
			if err != nil || cip == nil {
				t.Fatal("header cipher")
			}
			hash := make([]byte, 4)
			cip.XORKeyStream(hash, hash)
			_, original, _ := d.DeterminePacketTypeAndPadding(packet, hash)
			if name == "ambiguous-transport.bin" && original != MessageResponseType {
				t.Fatal("fixture no longer reproduces original problem")
			}
			padding, ok := d.vpn013AuthenticatedTransport(packet, hash)
			if !ok || padding != p.S["transport"] {
				t.Fatal("valid authenticated transport not recovered")
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("original datagram was modified")
			}
			tampered := append([]byte(nil), packet...)
			tampered[len(tampered)-1] ^= 1
			if _, ok := d.vpn013AuthenticatedTransport(tampered, hash); ok {
				t.Fatal("tampered data accepted")
			}
			d.indexTable.Delete(p.Index)
			if _, ok := d.vpn013AuthenticatedTransport(packet, hash); ok {
				t.Fatal("unknown receiver accepted")
			}
			d.indexTable.table[p.Index] = IndexTableEntry{peer: &Peer{}, keypair: &Keypair{receive: aead, created: time.Now().Add(-24 * time.Hour)}}
			if _, ok := d.vpn013AuthenticatedTransport(packet, hash); ok {
				t.Fatal("expired receiver accepted")
			}
			d.indexTable.table[p.Index] = IndexTableEntry{peer: &Peer{}, keypair: &Keypair{receive: aead, created: time.Now()}}
		})
	}
	if _, ok := d.vpn013AuthenticatedTransport([]byte{1, 2}, []byte{0, 0, 0, 0}); ok {
		t.Fatal("short datagram accepted")
	}
	if _, ok := d.vpn013AuthenticatedTransport(make([]byte, 64), nil); ok {
		t.Fatal("missing type hash accepted")
	}
	// Even if the transport header and a live receiver index happen to match,
	// unauthenticated control packets must stay on their original path.
	d.headerProtection.key = HeaderCipherKey{}
	for _, tc := range []struct {
		name        string
		messageType uint32
		messageSize int
	}{
		{"initiation", MessageInitiationType, MessageInitiationSize},
		{"response", MessageResponseType, MessageResponseSize},
		{"cookie_reply", MessageCookieReplyType, MessageCookieReplySize},
	} {
		t.Run("control-"+tc.name, func(t *testing.T) {
			packet := make([]byte, int(p.S[tc.name])+tc.messageSize+200)
			binary.LittleEndian.PutUint32(packet[p.S[tc.name]:], p.H[tc.name][0])
			binary.LittleEndian.PutUint32(packet[p.S["transport"]:], p.H["transport"][0])
			binary.LittleEndian.PutUint32(packet[p.S["transport"]+4:], p.Index)
			before := append([]byte(nil), packet...)
			hash := make([]byte, 4)
			_, kind, _ := d.DeterminePacketTypeAndPadding(packet, hash)
			if kind != tc.messageType {
				t.Fatalf("control path changed: %s", tc.name)
			}
			if _, ok := d.vpn013AuthenticatedTransport(packet, hash); ok {
				t.Fatal("unauthenticated control packet stolen")
			}
			if !bytes.Equal(packet, before) {
				t.Fatal("control packet changed")
			}
		})
	}
}
