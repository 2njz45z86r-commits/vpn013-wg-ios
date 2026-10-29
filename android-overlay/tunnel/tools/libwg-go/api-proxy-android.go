//go:build android

// SPDX-License-Identifier: MIT
package main

/*
#include <stdlib.h>
#include "r013_android_bridge.h"
*/
import "C"

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-android/r013proxy"
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/tun"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/grpc"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/websocket"
	"golang.org/x/sys/unix"
)

var r013ProxyActive atomic.Bool
var r013ProxyProbeState struct {
	sync.Mutex
	cancel context.CancelFunc
	route  *r013proxy.Route
	done   chan struct{}
}

func r013CancelProxyProbe() bool {
	r013ProxyProbeState.Lock()
	cancel, route, done := r013ProxyProbeState.cancel, r013ProxyProbeState.route, r013ProxyProbeState.done
	r013ProxyProbeState.Unlock()
	if cancel != nil {
		cancel()
	}
	if route != nil {
		route.Close()
	}
	if done == nil {
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(10 * time.Second):
		return false
	}
}

//export r013ProxyProbe
func r013ProxyProbe(raw *C.char, gate C.longlong) (result C.longlong) {
	result = -1
	if raw == nil || gate <= 0 {
		return
	}
	text := C.GoString(raw)
	if len(text) == 0 || len(text) > 1048576 {
		return
	}
	var shape struct {
		Inbounds  []json.RawMessage
		Outbounds []struct {
			Protocol string
			Settings struct{ Vnext []struct{ Address string } }
		}
	}
	if json.Unmarshal([]byte(text), &shape) != nil || len(shape.Inbounds) != 0 || len(shape.Outbounds) != 1 || shape.Outbounds[0].Protocol != "vless" || len(shape.Outbounds[0].Settings.Vnext) != 1 || net.ParseIP(shape.Outbounds[0].Settings.Vnext[0].Address) == nil {
		return
	}
	r013ProxyProbeState.Lock()
	if r013ProxyProbeState.done != nil {
		r013ProxyProbeState.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	route := r013proxy.NewRoute(func(socket uintptr) bool {
		return socket <= 0x7fffffff && C.r013_gate_prepare(C.uint64_t(gate), 1, C.int(socket)) == 1
	})
	done := make(chan struct{})
	r013ProxyProbeState.cancel = cancel
	r013ProxyProbeState.route = route
	r013ProxyProbeState.done = done
	r013ProxyProbeState.Unlock()
	var instance *core.Instance
	defer func() {
		cancel()
		route.Close()
		if instance != nil {
			_ = instance.Close()
		}
		r013ProxyProbeState.Lock()
		r013ProxyProbeState.cancel = nil
		r013ProxyProbeState.route = nil
		r013ProxyProbeState.done = nil
		close(done)
		r013ProxyProbeState.Unlock()
		if recover() != nil {
			result = -1
		}
	}()
	config, err := serial.LoadJSONConfig(bytes.NewReader([]byte(text)))
	if err != nil {
		return
	}
	instance, err = core.NewWithContext(route.Context(ctx), config)
	if err != nil {
		return
	}
	route.Bind(instance)
	if instance.Start() != nil {
		return
	}
	transport := &http.Transport{Proxy: nil, TLSHandshakeTimeout: 4 * time.Second, DisableKeepAlives: true, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
		destination, err := xnet.ParseDestination(network + ":" + address)
		if err != nil {
			return nil, err
		}
		return core.Dial(route.Context(c), instance, destination)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", "https://www.gstatic.com/generate_204", nil)
	if err != nil {
		return
	}
	request.Header.Set("Cache-Control", "no-store")
	begin := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_ = response.Body.Close()
	if response.StatusCode != 204 || ctx.Err() != nil {
		return
	}
	return C.longlong(time.Since(begin).Milliseconds())
}

var r013Proxy struct {
	sync.Mutex
	core  *core.Instance
	route *r013proxy.Route
	gate  uint64
	fd    int
}

//export r013ProxyStart
func r013ProxyStart(ticket C.longlong, raw *C.char, fd C.int, gate C.longlong) (result C.int) {
	r013Proxy.Lock()
	defer r013Proxy.Unlock()
	result = -1
	if !r013Valid(uint64(ticket)) || r013Proxy.core != nil || raw == nil || fd < 0 || gate <= 0 {
		return
	}
	tunnelHandlesMu.RLock()
	busy := len(tunnelHandles) != 0
	tunnelHandlesMu.RUnlock()
	if busy {
		return
	}
	text := C.GoString(raw)
	if len(text) == 0 || len(text) > 1048576 {
		return
	}
	// Only our constructed numeric-endpoint TUN configuration crosses this ABI.
	var shape struct {
		Inbounds []struct {
			Protocol string `json:"protocol"`
		}
		Outbounds []struct {
			Protocol string `json:"protocol"`
			Settings struct {
				Vnext []struct {
					Address string `json:"address"`
				}
			} `json:"settings"`
		}
	}
	if json.Unmarshal([]byte(text), &shape) != nil || len(shape.Inbounds) != 1 || shape.Inbounds[0].Protocol != "tun" || len(shape.Outbounds) < 1 || shape.Outbounds[0].Protocol != "vless" || len(shape.Outbounds[0].Settings.Vnext) != 1 || net.ParseIP(shape.Outbounds[0].Settings.Vnext[0].Address) == nil {
		return
	}
	duplicate, err := unix.Dup(int(fd))
	if err != nil {
		return
	}
	route := r013proxy.NewRoute(func(socket uintptr) bool {
		return socket <= 0x7fffffff && C.r013_gate_prepare(C.uint64_t(gate), 1, C.int(socket)) == 1
	})
	var instance *core.Instance
	keep := false
	previous, had := os.LookupEnv("XRAY_TUN_FD")
	defer func() {
		if had {
			_ = os.Setenv("XRAY_TUN_FD", previous)
		} else {
			_ = os.Unsetenv("XRAY_TUN_FD")
		}
		if recover() != nil {
			result = -6
			keep = false
		}
		if !keep {
			route.Close()
			if instance != nil {
				_ = instance.Close()
			}
			_ = unix.Close(duplicate)
		}
	}()
	if os.Setenv("XRAY_TUN_FD", strconv.Itoa(duplicate)) != nil {
		return
	}
	config, err := serial.LoadJSONConfig(bytes.NewReader([]byte(text)))
	if err != nil {
		result = -2
		return
	}
	instance, err = core.NewWithContext(route.Context(context.Background()), config)
	if err != nil {
		result = -3
		return
	}
	route.Bind(instance)
	if instance.Start() != nil {
		result = -4
		return
	}
	r013Proxy.core = instance
	r013Proxy.route = route
	r013Proxy.gate = uint64(gate)
	r013Proxy.fd = duplicate
	r013ProxyActive.Store(true)
	keep = true
	return 0
}

//export r013ProxyStop
func r013ProxyStop(ticket C.longlong) C.int {
	if !r013Valid(uint64(ticket)) {
		return -1
	}
	r013Proxy.Lock()
	defer r013Proxy.Unlock()
	if r013Proxy.core == nil {
		return 0
	}
	r013Proxy.route.Close()
	if r013Proxy.core.Close() != nil {
		return -2
	}
	_ = unix.Close(r013Proxy.fd)
	C.r013_gate_release(C.uint64_t(r013Proxy.gate))
	r013Proxy.core = nil
	r013Proxy.route = nil
	r013ProxyActive.Store(false)
	return 0
}

//export r013ProxyStats
func r013ProxyStats() *C.char {
	r013Proxy.Lock()
	defer r013Proxy.Unlock()
	if r013Proxy.core == nil {
		return nil
	}
	manager, ok := r013Proxy.core.GetFeature(stats.ManagerType()).(stats.Manager)
	if !ok {
		return nil
	}
	read := func(name string) int64 {
		c := manager.GetCounter(name)
		if c == nil {
			return 0
		}
		return c.Value()
	}
	wire, _ := json.Marshal(map[string]int64{"rx": read("inbound>>>vpn013-tun>>>traffic>>>downlink"), "tx": read("inbound>>>vpn013-tun>>>traffic>>>uplink")})
	return C.CString(string(wire))
}
