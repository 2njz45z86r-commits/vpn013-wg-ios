// SPDX-License-Identifier: MIT
package awgprobe

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

var ErrProbeBudget = errors.New("configuration exceeds the experimental probe resource budget")

// These are conservative limits for the isolated experiment, not edits to a
// saved configuration or claims about the physical iOS extension's footprint.
// Upstream accepts uint32 junk counts and negative obfuscator lengths; allowing
// those unchecked could allocate huge buffers or panic before a Bind sees data.
func validateProbeResources(config string) error {
	if len(config) > 64*1024 || strings.Count(config, "\n") > 1024 {
		return ErrProbeBudget
	}
	values := map[string]uint64{"jc": 0, "jmin": 0, "jmax": 0}
	for _, line := range strings.Split(config, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil || n > 4096 || key == "jc" && n > 64 {
				return ErrProbeBudget
			}
			values[key] = n
		case "i1", "i2", "i3", "i4", "i5":
			if !boundedInitialPacket(value) {
				return ErrProbeBudget
			}
		}
	}
	if values["jc"] > 0 && values["jmax"] < values["jmin"] {
		return ErrProbeBudget
	}
	return nil
}

// Mirrors the pinned upstream obfuscator length rules for an initial packet,
// whose input payload is empty. Unknown tags fail closed instead of guessing a
// bound. This does not generate, modify or log any configured packet content.
func boundedInitialPacket(spec string) bool {
	var size uint64
	for {
		start := strings.IndexByte(spec, '<')
		if start < 0 {
			return true
		}
		spec = spec[start+1:]
		end := strings.IndexByte(spec, '>')
		if end < 0 {
			return false
		}
		parts := strings.Fields(spec[:end])
		spec = spec[end+1:]
		if len(parts) == 0 || len(parts) > 2 {
			return false
		}
		value := ""
		if len(parts) == 2 {
			value = parts[1]
		}
		var n uint64
		switch parts[0] {
		case "r", "rc", "rd", "dz":
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil || parsed > 4096 {
				return false
			}
			n = parsed
		case "t":
			n = 4
		case "d", "ds":
			n = 0
		case "b":
			value = strings.TrimPrefix(value, "0x")
			if len(value) == 0 || len(value) > 8192 || len(value)%2 != 0 {
				return false
			}
			if _, err := hex.DecodeString(value); err != nil {
				return false
			}
			n = uint64(len(value) / 2)
		default:
			return false
		}
		size += n
		if size > 4096 {
			return false
		}
	}
}
