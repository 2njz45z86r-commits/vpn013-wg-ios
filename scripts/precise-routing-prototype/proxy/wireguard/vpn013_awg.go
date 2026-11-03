// SPDX-License-Identifier: MIT
// Isolated prototype. Not a reviewed or released client implementation.
package wireguard

import (
	"errors"
	"sort"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// Match the actual AWG UAPI range parser without returning its input in errors.
func VPN013ValidateKeepAlive(value string) error {
	if len(value) == 0 || len(value) > 21 {
		return errors.New("invalid WireGuard keepalive")
	}
	var parsed device.UintRange
	if err := parsed.FromString(value); err != nil {
		return errors.New("invalid WireGuard keepalive")
	}
	return nil
}

var vpn013AllowedAWGFields = map[string]bool{
	"r013_legacy15": true, "jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
	"j1": true, "j2": true, "j3": true, "itime": true,
	"header_protection_key": true, "content_padding_addition": true,
	"rekey_after_time": true, "rekey_timeout": true, "reject_after_time": true,
	"keepalive_timeout": true, "max_handshake_attempts": true,
	"random_trailers": true, "disable_cookies": true,
}

// Validate the transport envelope before the AWG core's stricter UAPI parser.
// The legacy flag goes first because it governs parsing of later I/J fields.
func VPN013AWGLines(fields map[string]string) ([]string, error) {
	if len(fields) > len(vpn013AllowedAWGFields) {
		return nil, errors.New("invalid AWG field count")
	}
	keys := make([]string, 0, len(fields))
	total := 0
	for key, value := range fields {
		if !vpn013AllowedAWGFields[key] || len(value) > 16384 {
			return nil, errors.New("invalid AWG field")
		}
		total += len(key) + len(value) + 2
		if total > 98304 {
			return nil, errors.New("AWG settings too large")
		}
		for _, b := range []byte(value) {
			if b < 0x20 || b > 0x7e || b == '=' {
				return nil, errors.New("invalid AWG field encoding")
			}
		}
		if key == "r013_legacy15" && value != "true" && value != "false" {
			return nil, errors.New("invalid AWG mode")
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	if legacy, ok := fields["r013_legacy15"]; ok {
		result = append(result, "r013_legacy15="+legacy+"\n")
	}
	for _, key := range keys {
		if key != "r013_legacy15" {
			result = append(result, key+"="+strings.Clone(fields[key])+"\n")
		}
	}
	return result, nil
}
