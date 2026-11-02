package device

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestVPN013AuthenticatedControlFallback(t *testing.T) {
	for _, protected := range []bool{false, true} {
		for _, kind := range []string{"response", "cookie"} {
			name := kind + "-plain"
			if protected {
				name = kind + "-protected"
			}
			t.Run(name, func(t *testing.T) {
				d := new(Device)
				d.randomTrailers.Store(true)
				d.paddings.init.Store(12)
				d.paddings.response.Store(32)
				d.paddings.cookie.Store(48)
				d.paddings.transport.Store(16)
				var r UintRange
				r.FromUint32(1, 1)
				d.headers.init.Store(r)
				r.FromUint32(2, 2)
				d.headers.response.Store(r)
				r.FromUint32(3, 3)
				d.headers.cookie.Store(r)
				r.FromUint32(4, 4)
				d.headers.transport.Store(r)
				if protected {
					d.headerProtection.key[0] = 7
				}
				var public NoisePublicKey
				public[0] = 42
				d.cookieChecker.Init(public)
				var sender CookieGenerator
				sender.Init(public)
				var frame []byte
				var wanted uint32
				var padding uint32
				var peer Peer
				var reply *MessageCookieReply
				if kind == "response" {
					wanted = MessageResponseType
					padding = 32
					frame = make([]byte, MessageResponseSize)
					binary.LittleEndian.PutUint32(frame[:4], 2)
					sender.AddMacs(frame)
				} else {
					wanted = MessageCookieReplyType
					padding = 48
					peer.cookieGenerator.Init(public)
					initiation := make([]byte, MessageInitiationSize)
					peer.cookieGenerator.AddMacs(initiation)
					replyValue, err := d.cookieChecker.CreateReply(initiation, 123, []byte{127, 0, 0, 1}, 3)
					if err != nil {
						t.Fatal(err)
					}
					reply = replyValue
					buffer := new(bytes.Buffer)
					if err := binary.Write(buffer, binary.LittleEndian, reply); err != nil {
						t.Fatal(err)
					}
					frame = buffer.Bytes()
					d.indexTable.Init()
					d.indexTable.table[123] = IndexTableEntry{peer: &peer}
				}
				packet := make([]byte, int(padding)+len(frame)+200)
				for i := 0; i < HeaderCipherNonceSize; i++ {
					packet[i] = byte(i + 1)
				}
				hash := make([]byte, 4)
				cipher, err := d.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
				if err != nil {
					t.Fatal(err)
				}
				if cipher != nil {
					cipher.XORKeyStream(frame, frame)
					other, err := d.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
					if err != nil {
						t.Fatal(err)
					}
					other.XORKeyStream(hash, hash)
				}
				copy(packet[int(padding):], frame)
				binary.LittleEndian.PutUint32(packet[12:16], 1^binary.LittleEndian.Uint32(hash))
				before := append([]byte(nil), packet...)
				_, original, _ := d.DeterminePacketTypeAndPadding(packet, hash)
				if original != MessageInitiationType {
					t.Fatal("control collision not reproduced")
				}
				_, got, off, ok := d.vpn013AuthenticatedControl(packet, hash, false)
				if !ok || got != wanted || off != padding {
					t.Fatalf("legitimate %s was not recovered", kind)
				}
				if !bytes.Equal(packet, before) {
					t.Fatal("original frame modified")
				}
				bad := append([]byte(nil), packet...)
				bad[int(padding)+20] ^= 1
				if _, _, _, ok := d.vpn013AuthenticatedControl(bad, hash, false); ok {
					t.Fatal("tampered control accepted")
				}
				if kind == "cookie" {
					if !peer.cookieGenerator.mac2.cookieSet.IsZero() {
						t.Fatal("validation consumed cookie state")
					}
					if !peer.cookieGenerator.ConsumeReply(reply) {
						t.Fatal("valid cookie could not be consumed afterwards")
					}
				}
			})
		}
	}
}
