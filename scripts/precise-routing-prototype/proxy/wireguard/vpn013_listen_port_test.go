package wireguard

import (
	"net"
	"testing"
)

// An explicit client port must not silently turn into an arbitrary local port.
// A future adapter may support it, but until then it must fail before binding.
func TestVPN013ExplicitListenPortNeverSilentlyIgnored(t *testing.T) {
	called := false
	b := &bind{listenFunc: func() (net.PacketConn, error) {
		called = true
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}}
	_, _, err := b.Open(24067)
	defer b.Close()
	if err == nil || called {
		t.Fatal("an unsupported explicit listen port must be rejected before opening a socket")
	}
}

func TestVPN013AutomaticListenPortStillWorks(t *testing.T) {
	b := &bind{listenFunc: func() (net.PacketConn, error) {
		return net.ListenPacket("udp4", "127.0.0.1:0")
	}}
	functions, actual, err := b.Open(0)
	defer b.Close()
	if err != nil || actual == 0 || len(functions) != 1 {
		t.Fatal("automatic port should bind a loopback socket")
	}
}
