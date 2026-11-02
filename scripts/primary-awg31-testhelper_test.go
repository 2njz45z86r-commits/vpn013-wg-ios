package device

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"time"
)

// Regression-only verifier for the public synthetic fixture.
// Prototype only: verify the transport candidate before overriding a control
// classification. No peer, replay-filter, counter, or original packet is changed.
func (device *Device) vpn013AuthenticatedTransport(packet, typeHash []byte) (uint32, bool) {
	padding := device.paddings.transport.Load()
	offset := int(padding)
	if len(typeHash) != 4 || offset > len(packet) || len(packet)-offset < MessageTransportSize || len(packet) < HeaderCipherNonceSize {
		return 0, false
	}
	var header [MessageTransportHeaderSize]byte
	copy(header[:], packet[offset:offset+MessageTransportHeaderSize])
	applyHash(header[:4], header[:4], typeHash)
	if !device.headers.transport.Load().Contains(binary.LittleEndian.Uint32(header[:4])) {
		return 0, false
	}
	cipher, err := device.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
	if err != nil {
		return 0, false
	}
	if cipher != nil {
		var prefix [4]byte
		cipher.XORKeyStream(prefix[:], prefix[:])
		cipher.XORKeyStream(header[4:], header[4:])
	}
	index := binary.LittleEndian.Uint32(header[MessageTransportOffsetReceiver:MessageTransportOffsetCounter])
	entry := device.indexTable.Lookup(index)
	if entry.peer == nil || entry.keypair == nil || entry.keypair.receive == nil || entry.keypair.created.Add(device.keychainExpireTime()).Before(time.Now()) {
		return 0, false
	}
	var nonce [chacha20poly1305.NonceSize]byte
	copy(nonce[4:], header[MessageTransportOffsetCounter:MessageTransportOffsetContent])
	plaintext, err := entry.keypair.receive.Open(nil, nonce[:], packet[offset+MessageTransportHeaderSize:], nil)
	if err != nil {
		return 0, false
	}
	clear(plaintext)
	return padding, true
}
