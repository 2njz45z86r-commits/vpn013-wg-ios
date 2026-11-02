package device

import (
	"sync"
	"testing"
)

// Synthetic loopback devices only. Exercise the existing header key lock and
// new classifier while the device receives valid UAPI key updates.
func TestVPN013HeaderProtectionConcurrentUpdates(t *testing.T) {
	const keyA = "d7068cea352177b603b321c845694f89c8174b47f926a5c59bd2a72065675736"
	const keyB = "e8068cea352177b603b321c845694f89c8174b47f926a5c59bd2a72065675737"
	pair := genTestPair(t, true, "s1", "16", "s2", "16", "s3", "16", "s4", "16", "header_protection_key", keyA)
	device := pair[0].dev
	salt := make([]byte, HeaderCipherNonceSize)
	var wg sync.WaitGroup
	errors := make(chan string, 4)
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < 400; i++ {
			key := keyA
			if i%2 == 1 {
				key = keyB
			}
			if err := device.IpcSet(uapiCfg("header_protection_key", key)); err != nil {
				errors <- "configuration rejected"
				return
			}
		}
	}()
	for n := 0; n < 3; n++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				cipher, err := device.HeaderProtectionCipher(salt)
				if err != nil || cipher == nil {
					errors <- "header cipher unavailable"
					return
				}
				packet := make([]byte, 200)
				hash := make([]byte, 4)
				cipher.XORKeyStream(hash, hash)
				_, _ = device.vpn013TransportCandidate(packet, hash)
				_, _, _, _ = device.vpn013AuthenticatedControl(packet, hash, true)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for msg := range errors {
		t.Error(msg)
	}
}
