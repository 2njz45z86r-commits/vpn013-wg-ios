//go:build cgo && r013_bridge_test

// SPDX-License-Identifier: MIT
// Test-only ABI exerciser. This symbol is excluded from the normal archive.
package main

/*
#include "r013_bridge.h"
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	awgprobe "github.com/amnezia-vpn/amneziawg-apple/r013probe"
	"net/netip"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
)

//export R013BridgeExercise
func R013BridgeExercise(driver C.uint64_t) C.int32_t {
	b, err := nativeBind(uint64(driver), netip.MustParseAddrPort("127.0.0.1:12345"))
	if err != nil {
		return 1
	}
	read, _, err := b.Open(0)
	if err != nil {
		return 2
	}
	defer b.Close()
	// A live driver must never be unregistered from underneath its UDP bind.
	if R013UnregisterUDPDriver(driver) == 0 {
		return 3
	}
	ep, _ := b.ParseEndpoint("127.0.0.1:12345")
	request := []byte("r013-native-bridge")
	if b.Send([][]byte{request}, ep) != nil {
		return 4
	}
	packet := make([]byte, 64)
	sizes := make([]int, 1)
	readDone := make(chan bool, 1)
	go func() {
		n, err := read[0]([][]byte{packet}, sizes, make([]conn.Endpoint, 1))
		readDone <- err == nil && n == 1 && bytes.Equal(packet[:sizes[0]], request)
	}()
	select {
	case ok := <-readDone:
		if !ok {
			return 5
		}
	case <-time.After(time.Second):
		b.Close()
		<-readDone
		return 5
	}
	if b.Close() != nil {
		return 6
	}
	return 0
}

//export R013BridgeDNSExercise
func R013BridgeDNSExercise(driver C.uint64_t) C.int32_t {
	value, ok := drivers.Load(uint64(driver))
	if !ok {
		return 1
	}
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return 2
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return 2
	}
	// Synthetic identity only: no actual primary VPN is started by this test.
	guard, err := awgprobe.NewActiveGuard(awgprobe.ActiveState{Known: true, Configuration: "private_key=" + hex.EncodeToString(client.Bytes()) + "\npublic_key=" + hex.EncodeToString(server.PublicKey().Bytes()) + "\n"})
	if err != nil {
		return 3
	}
	target := netip.MustParseAddrPort("127.0.0.1:12345")
	result, err := awgprobe.MeasureCurrentDNS(context.Background(), awgprobe.CurrentDNSRequest{Target: target, Factory: nativeTunnelFactory{value.(*nativeDriver)}, Guard: guard})
	if err != nil || result.Samples != 3 || result.Method != "dns-udp-challenge-v1" || result.Target != target || !guard.Accept(result) {
		return 4
	}
	return 0
}
