// SPDX-License-Identifier: MIT
package r013gate

import (
	"github.com/amnezia-vpn/amneziawg-windows-client/r013probe/protectedudp"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013winudp"
	"golang.org/x/sys/windows"
)

// NewFactory requires a token held by the actual cross-process comparison
// barrier and immutable interface indexes. Callers must obtain those indexes
// from native observed primary/route state; this API never guesses them.
// Separate factories fix physical/current roles permanently. Invalidating a
// token prevents new sockets; the owner MUST Close and drain before returning
// from Candidate so the primary mutation can acquire the kernel mutex.
func NewUDPFactory(role int, ipv4, ipv6 uint32, token Token) (*protectedudp.Factory, error) {
	if !token.Valid() || role != protectedudp.Physical && role != protectedudp.ThroughTunnel || ipv4 == 0 && ipv6 == 0 {
		return nil, r013winudp.ErrBind
	}
	return protectedudp.NewForNetwork(role, &routeGate{role, ipv4, ipv6, token})
}

type routeGate struct {
	role       int
	ipv4, ipv6 uint32
	token      Token
}

func (g *routeGate) PrepareNetwork(role int, network string, fd uintptr) error {
	if role != g.role || !g.token.Valid() {
		return r013winudp.ErrBind
	}
	family, index := windows.AF_INET, g.ipv4
	switch network {
	case "udp4":
	case "udp6":
		family, index = windows.AF_INET6, g.ipv6
	default:
		return r013winudp.ErrBind
	}
	if r013winudp.Pin(fd, family, index) != nil || !g.token.Valid() {
		return r013winudp.ErrBind
	}
	return nil
}
