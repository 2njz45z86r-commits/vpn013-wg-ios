// SPDX-License-Identifier: MIT
// Isolated prototype: hold queued TUN events until UAPI configuration is set.
package wireguard

import (
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type vpn013GatedTUN struct {
	tun.Device
	release     chan struct{}
	done        chan struct{}
	events      chan tun.Event
	releaseOnce sync.Once
	closeOnce   sync.Once
	closeErr    error
}

func newVPN013GatedTUN(device tun.Device) *vpn013GatedTUN {
	g := &vpn013GatedTUN{Device: device, release: make(chan struct{}), done: make(chan struct{}), events: make(chan tun.Event)}
	go func() {
		defer close(g.events)
		select {
		case <-g.release:
		case <-g.done:
			return
		}
		for {
			select {
			case <-g.done:
				return
			case event, ok := <-device.Events():
				if !ok {
					return
				}
				select {
				case g.events <- event:
				case <-g.done:
					return
				}
			}
		}
	}()
	return g
}
func (g *vpn013GatedTUN) Events() <-chan tun.Event { return g.events }
func (g *vpn013GatedTUN) enableEvents()            { g.releaseOnce.Do(func() { close(g.release) }) }
func (g *vpn013GatedTUN) Close() error {
	g.closeOnce.Do(func() { close(g.done); g.closeErr = g.Device.Close() })
	return g.closeErr
}
