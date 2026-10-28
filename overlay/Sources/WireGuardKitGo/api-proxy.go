//go:build darwin

// SPDX-License-Identifier: MIT
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"
	"golang.org/x/sys/unix"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"
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
)

// One shared Go archive avoids duplicate Go runtimes in the extension. Proxy
// starts are serialized; the caller must stop the previously selected VPN.
var r013Proxy struct {
	sync.Mutex
	instance            *core.Instance
	fd                  int
	previousMemoryLimit int64
}

//export R013ProxyValidate
func R013ProxyValidate(raw *C.char) C.int {
	if raw == nil {
		return -1
	}
	text := C.GoString(raw)
	if len(text) == 0 || len(text) > 1048576 {
		return -1
	}
	if _, err := serial.LoadJSONConfig(bytes.NewReader([]byte(text))); err != nil {
		return -4
	}
	return 0
}

//export R013ProxyStart
func R013ProxyStart(raw *C.char, fd C.int) (result C.int) {
	r013Proxy.Lock()
	defer r013Proxy.Unlock()
	if r013Proxy.instance != nil {
		return -2
	}
	if raw == nil || fd < 0 {
		return -1
	}
	text := C.GoString(raw)
	if len(text) == 0 || len(text) > 1048576 || !json.Valid([]byte(text)) {
		return -1
	}
	// Never take ownership of NetworkExtension's descriptor. The pinned TUN
	// implementation treats an injected fd as externally owned; close OUR dup
	// only after the core has stopped reading it.
	duplicate, err := unix.Dup(int(fd))
	if err != nil {
		return -3
	}
	keep := false
	var pending *core.Instance
	previousMemoryLimit := int64(0)
	limited := false
	previousEnvironment, hadEnvironment := os.LookupEnv("XRAY_TUN_FD")
	defer func() {
		if recover() != nil {
			result = -6
			keep = false
		}
		if hadEnvironment {
			_ = os.Setenv("XRAY_TUN_FD", previousEnvironment)
		} else {
			_ = os.Unsetenv("XRAY_TUN_FD")
		}
		if !keep {
			if pending != nil {
				_ = pending.Close()
			}
			_ = unix.Close(duplicate)
			if limited {
				debug.SetMemoryLimit(previousMemoryLimit)
			}
		}
	}()
	if err = os.Setenv("XRAY_TUN_FD", strconv.Itoa(duplicate)); err != nil {
		return -3
	}
	previousMemoryLimit = debug.SetMemoryLimit(40 << 20) // Soft GC target, not an extension-RSS guarantee.
	limited = true
	configuration, err := serial.LoadJSONConfig(bytes.NewReader([]byte(text)))
	if err != nil {
		return -4
	}
	instance, err := core.New(configuration)
	pending = instance
	if err != nil {
		return -4
	}
	if err = instance.Start(); err != nil {
		return -5
	}
	r013Proxy.instance, r013Proxy.fd = instance, duplicate
	r013Proxy.previousMemoryLimit = previousMemoryLimit
	keep = true
	return 0
}

//export R013ProxyStop
func R013ProxyStop() {
	r013Proxy.Lock()
	defer r013Proxy.Unlock()
	if r013Proxy.instance != nil {
		_ = r013Proxy.instance.Close()
		_ = unix.Close(r013Proxy.fd)
		r013Proxy.instance = nil
		debug.SetMemoryLimit(r013Proxy.previousMemoryLimit)
	}
}

//export R013ProxyStatistics
func R013ProxyStatistics() *C.char {
	r013Proxy.Lock()
	defer r013Proxy.Unlock()
	value := struct {
		Running bool  `json:"running"`
		RX      int64 `json:"rx"`
		TX      int64 `json:"tx"`
	}{Running: r013Proxy.instance != nil}
	if r013Proxy.instance != nil {
		if manager, ok := r013Proxy.instance.GetFeature(stats.ManagerType()).(stats.Manager); ok {
			if counter := manager.GetCounter("inbound>>>vpn013-tun>>>traffic>>>uplink"); counter != nil {
				value.TX = counter.Value()
			}
			if counter := manager.GetCounter("inbound>>>vpn013-tun>>>traffic>>>downlink"); counter != nil {
				value.RX = counter.Value()
			}
		}
	}
	raw, _ := json.Marshal(value)
	return C.CString(string(raw)) // Swift owns/free()s only this returned buffer.
}
