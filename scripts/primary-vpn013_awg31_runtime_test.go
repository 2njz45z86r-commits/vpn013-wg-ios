package device

import (
	"testing"
	"time"
)

func TestVPN013PaddingFitsPeerWindow(t *testing.T) {
	d := new(Device)
	var r UintRange
	r.FromUint32(100, 100)
	d.contentPaddingAddition.Store(r)
	peer := &Peer{device: d}
	peer.udpWindow.Store(1280)
	for _, tc := range []struct{ packet, want int }{{1100, 100}, {1270, 10}, {1280, 0}, {1281, 0}, {2000, 0}} {
		if got := peer.randomPaddingAddition(tc.packet); got != tc.want {
			t.Fatalf("packet=%d got=%d want=%d", tc.packet, got, tc.want)
		}
	}
	d.contentPaddingAddition.Store(UintRange(0))
	if got := peer.randomPaddingAddition(100); got != -1 {
		t.Fatalf("disabled padding returned %d", got)
	}
}

func TestVPN013DisabledCookiesPermitLoadedHandshake(t *testing.T) {
	pair := genTestPair(t, true, "disable_cookies", "true")
	for i := range pair {
		pair[i].dev.rate.underLoadUntil.Store(time.Now().Add(30 * time.Second).UnixNano())
	}
	pair.Send(t, Ping, nil)
	pair.Send(t, Pong, nil)
}
