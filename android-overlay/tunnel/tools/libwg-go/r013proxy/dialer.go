// SPDX-License-Identifier: MIT
package r013proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet"
)

var errRoute = errors.New("physical socket route unavailable")

type routeKey struct{}

var instanceRoutes sync.Map

// Route owns one immutable Android Network gate and every socket opened for it.
// A retired gate is never replaced by the process's current/default VPN route.
type Route struct {
	mu      sync.Mutex
	closed  bool
	protect func(uintptr) bool
	sockets map[*ownedConn]struct{}
}

func NewRoute(protect func(uintptr) bool) *Route {
	return &Route{protect: protect, sockets: make(map[*ownedConn]struct{})}
}
func (r *Route) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, routeKey{}, r)
}
func (r *Route) Bind(instance *core.Instance) { instanceRoutes.Store(instance, r) }
func (r *Route) control(_, _ string, raw syscall.RawConn) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.protect == nil {
		return errRoute
	}
	ok := false
	if err := raw.Control(func(fd uintptr) { ok = r.protect(fd) }); err != nil {
		return err
	}
	if !ok {
		return errRoute
	}
	return nil
}
func (r *Route) Close() {
	instanceRoutes.Range(func(key, value any) bool {
		if value == r {
			instanceRoutes.Delete(key)
		}
		return true
	})
	r.mu.Lock()
	r.closed = true
	sockets := make([]*ownedConn, 0, len(r.sockets))
	for socket := range r.sockets {
		sockets = append(sockets, socket)
	}
	r.mu.Unlock()
	for _, socket := range sockets {
		_ = socket.Close()
	}
}

type ownedConn struct {
	net.Conn
	route *Route
	once  sync.Once
}

func (c *ownedConn) Close() error {
	var err error
	c.once.Do(func() { err = c.Conn.Close(); c.route.mu.Lock(); delete(c.route.sockets, c); c.route.mu.Unlock() })
	return err
}
func (r *Route) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(address)
	// Endpoints are resolved against the captured Android Network before start.
	// Never allow Go's default DNS resolver to recurse into this VPN.
	if err != nil || net.ParseIP(host) == nil || (network != "tcp" && network != "udp") {
		return nil, errRoute
	}
	d := net.Dialer{Timeout: 16 * time.Second, Control: r.control}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	owned := &ownedConn{Conn: conn, route: r}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		_ = conn.Close()
		return nil, errRoute
	}
	r.sockets[owned] = struct{}{}
	r.mu.Unlock()
	return owned, nil
}

type systemDialer struct{}

func (systemDialer) Dial(ctx context.Context, _ xnet.Address, dest xnet.Destination, _ *internet.SocketConfig) (net.Conn, error) {
	route, ok := ctx.Value(routeKey{}).(*Route)
	if !ok {
		if value, found := instanceRoutes.Load(core.FromContext(ctx)); found {
			route, ok = value.(*Route)
		}
	}
	if !ok {
		return nil, errRoute
	}
	return route.dial(ctx, dest.Network.SystemString(), dest.NetAddr())
}
func (systemDialer) DestIpAddress() net.IP { return nil }

// Installed once, before any instance starts; never swapped while workers run.
func init() { internet.UseAlternativeSystemDialer(systemDialer{}) }
