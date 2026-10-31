//go:build windows && r013_resource_fixture

// SPDX-License-Identifier: MIT
package r013resource

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

func TestPrimaryConfigResourceAndPrivateErrors(t *testing.T) {
	var keyBytes [32]byte // Synthetic nonzero key, never connected.
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])
	config := func(extra string) string {
		return "[Interface]\nPrivateKey = " + key + "\nAddress = 10.77.0.2/32\n" + extra +
			"\n[Peer]\nPublicKey = " + key + "\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:51820\n"
	}
	for name, extra := range map[string]string{
		"plain_wireguard": "",
		"bounded_awg":     "Jc = 3\nJmin = 40\nJmax = 70\nS1 = 20\nS2 = 20\nS3 = 20\nS4 = 20\nI1 = <r 20>\n",
		"maximum_budget":  "Jc = 64\nJmin = 4096\nJmax = 4096\nI1 = <r 4096>\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := conf.FromWgQuick(config(extra), "synthetic-resource-check"); err != nil {
				t.Fatal("valid bounded configuration rejected:", err)
			}
		})
	}
	for name, extra := range map[string]string{
		"reversed":         "Jc = 1\nJmin = 100\nJmax = 10\n",
		"high_count":       "Jc = 65535\nJmin = 65535\nJmax = 65535\n",
		"large_packet":     "Jc = 1\nJmin = 0\nJmax = 4097\n",
		"large_padding":    "S1 = 4097\n",
		"negative_initial": "I1 = <r -1>\n",
		"huge_initial":     "I1 = <r 999999999>\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := conf.FromWgQuick(config(extra), "synthetic-resource-check"); err == nil {
				t.Fatal("unsafe configuration accepted by the actual import parser")
			}
		})
	}
	const sentinel = "SYNTHETIC_PRIVATE_VALUE_MUST_NOT_ENTER_DIAGNOSTICS"
	for name, text := range map[string]string{
		"private_key_error":   strings.Replace(config(""), "PrivateKey = "+key, "PrivateKey = "+sentinel, 1),
		"preshared_key_error": strings.Replace(config(""), "[Peer]\n", "[Peer]\nPresharedKey = "+sentinel+"\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := conf.FromWgQuick(text, "synthetic-resource-check")
			if err == nil || strings.Contains(err.Error(), sentinel) {
				t.Fatal("malformed key error is missing or reveals supplied private text")
			}
		})
	}
}
