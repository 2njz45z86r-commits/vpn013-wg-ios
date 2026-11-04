package device

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestVPN013ClassifierMalformedFramesDoNotPanic(t *testing.T) {
	d := new(Device)
	d.indexTable.Init()
	d.cookieChecker.Init(NoisePublicKey{})
	var r UintRange
	r.FromUint32(0, ^uint32(0))
	d.headers.init.Store(r)
	d.headers.response.Store(r)
	d.headers.cookie.Store(r)
	d.headers.transport.Store(r)
	d.randomTrailers.Store(true)
	random := rand.New(rand.NewSource(13013))
	for i := 0; i < 20000; i++ {
		packet := make([]byte, random.Intn(300))
		_, _ = random.Read(packet)
		before := append([]byte(nil), packet...)
		d.paddings.init.Store(uint32(random.Intn(400)))
		d.paddings.response.Store(uint32(random.Intn(400)))
		d.paddings.cookie.Store(uint32(random.Intn(400)))
		d.paddings.transport.Store(uint32(random.Intn(400)))
		if i%7 == 0 {
			d.paddings.init.Store(^uint32(0))
			d.paddings.transport.Store(^uint32(0))
		}
		d.headerProtection.key = HeaderCipherKey{}
		if i%2 == 0 {
			d.headerProtection.key[0] = 7
		}
		hash := make([]byte, 4)
		_, _ = random.Read(hash)
		if i%5 == 0 {
			hash = nil
		}
		_, _ = d.vpn013AuthenticatedTransport(packet, hash)
		_, _ = d.vpn013TransportCandidate(packet, hash)
		_, _, _, _ = d.vpn013AuthenticatedControl(packet, hash, false)
		_, _, _, _ = d.vpn013AuthenticatedControl(packet, hash, true)
		if !bytes.Equal(packet, before) {
			t.Fatalf("input changed at %d", i)
		}
	}
}
