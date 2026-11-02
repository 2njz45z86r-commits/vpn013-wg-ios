package awg

import (
	"sync"
	"testing"
)

// Synthetic reproduction of upstream v1.5 concurrent handshake generation.
// The shared read lock models device/send.go in the official implementation.
func TestVPN013LegacyConcurrentSpecialPackets(t *testing.T) {
	var h SpecialHandshakeHandler
	generator, err := Parse("i1", "<b 0xf1f2><c><t>")
	if err != nil {
		t.Fatal(err)
	}
	h.SpecialJunk.AppendGenerator(generator)
	var shared sync.RWMutex
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				shared.RLock()
				packets := h.GenerateSpecialJunk()
				shared.RUnlock()
				if len(packets) > 0 && (len(packets) != 1 || len(packets[0]) != 18) {
					t.Error("synthetic packet shape changed")
					return
				}
			}
		}()
	}
	wg.Wait()
}
