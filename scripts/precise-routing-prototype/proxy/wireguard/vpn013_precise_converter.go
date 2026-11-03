// SPDX-License-Identifier: MIT
// Isolated diagnostic prototype. Not linked to the iPhone application.
package wireguard

import (
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// VPN013ConvertedPeer and VPN013ConvertedSettings use Xray's JSON property
// names. They hold secret key material and must never be logged or persisted.
type VPN013ConvertedPeer struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	Endpoint     string   `json:"endpoint"`
	AllowedIPs   []string `json:"allowedIPs"`
	KeepAlive    string   `json:"vpn013KeepAlive,omitempty"`
}

type VPN013ConvertedSettings struct {
	NoKernelTun bool                  `json:"noKernelTun"`
	SecretKey   string                `json:"secretKey"`
	Address     []string              `json:"address"`
	MTU         int                   `json:"mtu"`
	Peers       []VPN013ConvertedPeer `json:"peers"`
	AWG         map[string]string     `json:"vpn013AWG,omitempty"`
}

// VPN013ConvertUAPI strictly converts one generated UAPI peer and an explicit
// effective MTU. It deliberately does not configure iOS routes, DNS or the TUN.
// Unknown input and explicit nonzero local listen ports fail closed.
func VPN013ConvertUAPI(input string, addresses []string, mtu int) (VPN013ConvertedSettings, error) {
	fail := func() (VPN013ConvertedSettings, error) {
		return VPN013ConvertedSettings{}, errors.New("unsupported or invalid WireGuard profile")
	}
	if len(input) == 0 || len(input) > 1<<20 || len(addresses) == 0 || len(addresses) > 32 || mtu < 576 || mtu > 65535 {
		return fail()
	}
	for _, address := range addresses {
		if _, err := netip.ParsePrefix(address); err != nil {
			return fail()
		}
	}
	result := VPN013ConvertedSettings{NoKernelTun: true, Address: append([]string(nil), addresses...), MTU: mtu, AWG: map[string]string{}}
	peer := VPN013ConvertedPeer{}
	seen := map[string]bool{}
	peerStarted := false
	validKey := func(value string) bool {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 32
	}
	for _, line := range strings.Split(input, "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(value, "\r\n\x00") || len(key) == 0 || (key != "allowed_ip" && seen[key]) {
			return fail()
		}
		seen[key] = true
		switch key {
		case "private_key":
			if peerStarted || !validKey(value) {
				return fail()
			}
			result.SecretKey = value
		case "replace_peers":
			if peerStarted || value != "true" {
				return fail()
			}
		case "listen_port":
			if peerStarted || value != "0" {
				return fail()
			}
		case "public_key":
			if peerStarted || !validKey(value) {
				return fail()
			}
			peerStarted = true
			peer.PublicKey = value
		case "preshared_key":
			if !peerStarted || !validKey(value) {
				return fail()
			}
			peer.PreSharedKey = value
		case "endpoint":
			if !peerStarted {
				return fail()
			}
			host, port, err := net.SplitHostPort(value)
			if err != nil || host == "" {
				return fail()
			}
			n, err := strconv.ParseUint(port, 10, 16)
			if err != nil || n == 0 {
				return fail()
			}
			peer.Endpoint = value
		case "replace_allowed_ips":
			if !peerStarted || value != "true" {
				return fail()
			}
		case "allowed_ip":
			if !peerStarted || len(peer.AllowedIPs) >= 256 {
				return fail()
			}
			if _, err := netip.ParsePrefix(value); err != nil {
				return fail()
			}
			peer.AllowedIPs = append(peer.AllowedIPs, value)
		case "persistent_keepalive_interval":
			if !peerStarted || VPN013ValidateKeepAlive(value) != nil {
				return fail()
			}
			peer.KeepAlive = value
		default:
			if peerStarted || !vpn013AllowedAWGFields[key] {
				return fail()
			}
			result.AWG[key] = value
		}
	}
	if result.SecretKey == "" || peer.PublicKey == "" || peer.Endpoint == "" || len(peer.AllowedIPs) == 0 {
		return fail()
	}
	if _, err := VPN013AWGLines(result.AWG); err != nil {
		return fail()
	}
	result.Peers = []VPN013ConvertedPeer{peer}
	return result, nil
}
