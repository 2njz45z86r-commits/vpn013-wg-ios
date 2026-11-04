package device

import (
	"encoding/binary"
	"golang.org/x/crypto/chacha20poly1305"
	"time"
)

// Disambiguate overlapping control candidates. Verify MAC1
// (or a cookie's AEAD) without consuming session state or altering the frame.
func (device *Device) vpn013AuthenticatedControl(packet, typeHash []byte, force bool) (int, uint32, uint32, bool) {
	if len(typeHash) != 4 || len(packet) < HeaderCipherNonceSize {
		return 0, 0, 0, false
	}
	specs := []struct {
		kind    uint32
		size    int
		padding uint32
		header  UintRange
	}{
		{MessageInitiationType, MessageInitiationSize, device.paddings.init.Load(), device.headers.init.Load()},
		{MessageResponseType, MessageResponseSize, device.paddings.response.Load(), device.headers.response.Load()},
		{MessageCookieReplyType, MessageCookieReplySize, device.paddings.cookie.Load(), device.headers.cookie.Load()},
	}
	var matching [3]int
	count := 0
	for i, s := range specs {
		end := int(s.padding) + s.size
		if end > len(packet) || (end != len(packet) && !device.randomTrailers.Load()) {
			continue
		}
		var kind [4]byte
		applyHash(kind[:], packet[int(s.padding):int(s.padding)+4], typeHash)
		if s.header.Contains(binary.LittleEndian.Uint32(kind[:])) {
			matching[count] = i
			count++
		}
	}
	if count == 0 || (count < 2 && !force) {
		return 0, 0, 0, false
	}
	for _, i := range matching[:count] {
		s := specs[i]
		start := int(s.padding)
		var storage [MessageInitiationSize]byte
		frame := storage[:s.size]
		copy(frame, packet[start:start+s.size])
		applyHash(frame[:4], frame[:4], typeHash)
		cipher, err := device.HeaderProtectionCipher(packet[:HeaderCipherNonceSize])
		if err != nil {
			continue
		}
		if cipher != nil {
			var prefix [4]byte
			cipher.XORKeyStream(prefix[:], prefix[:])
			cipher.XORKeyStream(frame[4:], frame[4:])
		}
		valid := false
		if s.kind == MessageCookieReplyType {
			valid = device.vpn013ValidateCookie(frame)
		} else {
			valid = device.cookieChecker.CheckMAC1(frame)
		}
		clear(frame)
		if valid {
			return s.size, s.kind, s.padding, true
		}
	}
	return 0, 0, 0, false
}

func (device *Device) vpn013ValidateCookie(frame []byte) bool {
	if len(frame) != MessageCookieReplySize {
		return false
	}
	receiver := binary.LittleEndian.Uint32(frame[4:8])
	entry := device.indexTable.Lookup(receiver)
	if entry.peer == nil {
		return false
	}
	generator := &entry.peer.cookieGenerator
	generator.RLock()
	defer generator.RUnlock()
	if !generator.mac2.hasLastMAC1 {
		return false
	}
	cipher, err := chacha20poly1305.NewX(generator.mac2.encryptionKey[:])
	if err != nil {
		return false
	}
	var cookie [16]byte
	_, err = cipher.Open(cookie[:0], frame[8:32], frame[32:64], generator.mac2.lastMAC1[:])
	clear(cookie[:])
	return err == nil
}

// Only identify a plausible transport frame. Its authenticity is checked later
// by the normal transport decryption worker, before any payload is delivered.
func (device *Device) vpn013TransportCandidate(packet, typeHash []byte) (uint32, bool) {
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
	return padding, true
}
