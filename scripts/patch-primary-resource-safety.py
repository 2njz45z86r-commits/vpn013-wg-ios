"""Bound the pinned AWG 3.1 primary device before parsing or sending obfuscation.

Run after platform source staging (including Windows' device-fence patch), and
before compiling. This patches only the exact structural anchors below. A
changed upstream device must be reviewed instead of silently rewritten.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys


assert len(sys.argv) in (2, 3), "usage: patch-primary-resource-safety.py [--module-root] ROOT"
module_layout = len(sys.argv) == 3 and sys.argv[1] == "--module-root"
assert len(sys.argv) == 2 or module_layout
root = Path(sys.argv[-1]).resolve()
cache = Path(subprocess.check_output(["go", "env", "GOMODCACHE"], text=True).strip()).resolve()
assert root != cache and not root.is_relative_to(cache), "never patch the global Go module cache"
device = (root / "device" if module_layout else
          root / "vendor/github.com/amnezia-vpn/amneziawg-go/v3/device")
if module_layout:
    assert (root / "go.mod").read_text(encoding="utf-8").startswith(
        "module github.com/amnezia-vpn/amneziawg-go/v3\n"
    ), "wrong Go module root"
paths = {name: device / name for name in
         ("device.go", "uapi.go", "send.go", "noise-protocol.go")}
for path in paths.values():
    assert path.is_file() and path.resolve().is_relative_to(root)
new_source = device / "r013_resource_limits.go"
new_test = device / "r013_resource_limits_test.go"
assert not new_source.exists() and not new_test.exists(), "resource guard already staged"
assert hashlib.sha256(paths["noise-protocol.go"].read_bytes()).hexdigest() == (
    "25a37bd5efd16579c3b0c502450ffaaf949810e03ece56faad39252a6e4feaee"
), "unknown pinned AWG noise source"
texts = {name: path.read_text(encoding="utf-8") for name, path in paths.items()}
before_hashes = {name: hashlib.sha256(path.read_bytes()).hexdigest()
                 for name, path in paths.items()}
base_hashes = {
    "device.go": "6d013e27d6b33c1ecaae1a1fbc4999e15a3a11252e302c580ea0f9027fa3ec21",
    "uapi.go": "7a88ac0cc50ea932336042d963183760e38a48fd8e055e0c0d00a4324cf1ef32",
    "send.go": "6e0a8ee228ccaf424f43b1c69df5d4a190f0bbb424110fe02a4704a75cf74396",
    "noise-protocol.go": "25a37bd5efd16579c3b0c502450ffaaf949810e03ece56faad39252a6e4feaee",
}
if module_layout:
    assert before_hashes == base_hashes, "unexpected Go module source"
else:
    assert before_hashes["send.go"] == base_hashes["send.go"], "unknown staged send source"


def replace(name: str, old: str, new: str) -> None:
    source = texts[name]
    assert source.count(old) == 1, (name, old[:90], source.count(old))
    texts[name] = source.replace(old, new, 1)


# A single lock covers snapshots and writes of J, S, and I; never allow a
# handshake to see a half-updated obfuscation profile.
replace("device.go", "type Device struct {",
        "type Device struct {\n\tobfuscation sync.RWMutex")
assert "r013PrimaryFence" in texts["device.go"] or (
    "func (device *Device) IpcSetOperation(" in texts["uapi.go"]
), "unexpected device staging order"

replace("uapi.go",
        """	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	return nil""",
        "	return nil")
replace("uapi.go",
        "\tscanner := bufio.NewScanner(r)\n\tfor scanner.Scan() {\n\t\tline := scanner.Text()",
        """	// Consume the entire framed set before changing peers, keys, ports, or
	// obfuscation. A scanner/read failure must leave the device untouched.
	scanner := bufio.NewScanner(r)
	var lines []string
	var totalBytes int
	for scanner.Scan() {
		line := scanner.Text()
		totalBytes += len(line) + 1
		if totalBytes > 16<<20 {
			return ipcErrorf(ipc.IpcErrorInvalid, "UAPI set request exceeds input limit")
		}
		lines = append(lines, line)
		if line == "" { break }
	}
	if err := scanner.Err(); err != nil {
		return ipcErrorf(ipc.IpcErrorIO, "failed to read input: %w", err)
	}
	if err := preflightObfuscationSet(lines, ipcDev); err != nil { return err }
	for _, line := range lines {""")

for key, field in (("jc", "count"), ("jmin", "min"), ("jmax", "max")):
    old = f"device.junk.{field}.Store(uint32({key}))"
    replace("uapi.go", old, f"ipcDev.junk.{field} = uint32({key})")
for index in range(5):
    replace("uapi.go", f"device.ipackets[{index}] = chain",
            f"ipcDev.ipackets[{index}] = chain")
for index in range(1, 6):
    old = (f'case "i{index}":\n\t\tchain, err := newObfChain(value)')
    new = (f'case "i{index}":\n'
           f'\t\tif _, err := ValidateInitialPacketSpec(value); err != nil {{\n'
           f'\t\t\treturn ipcErrorf(ipc.IpcErrorInvalid, "unsafe I{index}: %w", err)\n'
           f'\t\t}}\n\t\tchain, err := newObfChain(value)')
    replace("uapi.go", old, new)

replace("uapi.go", "\theaderProtectionKey HeaderCipherKey\n}",
        "\theaderProtectionKey HeaderCipherKey\n"
        "\tjunk struct { count, min, max uint32 }\n"
        "\tipackets [5]*obfChain\n}")
replace("uapi.go",
        "\td.paddings.init = device.paddings.init.Load()",
        "\tdevice.obfuscation.RLock()\n\td.paddings.init = device.paddings.init.Load()")
replace("uapi.go",
        "\td.headerProtectionKey = device.headerProtection.key\n}",
        "\td.junk.count = device.junk.count.Load()\n"
        "\td.junk.min = device.junk.min.Load()\n"
        "\td.junk.max = device.junk.max.Load()\n"
        "\td.ipackets = device.ipackets\n"
        "\tdevice.obfuscation.RUnlock()\n"
        "\td.headerProtectionKey = device.headerProtection.key\n}")
replace("uapi.go",
        "func (d *ipcSetDevice) mergeWithDevice(device *Device) error {\n",
        "func (d *ipcSetDevice) mergeWithDevice(device *Device) error {\n"
        "\tvar specs [5]string\n"
        "\tfor i, chain := range d.ipackets { if chain != nil { specs[i] = chain.Spec } }\n"
        "\tpaddings := [4]uint32{d.paddings.init, d.paddings.response, "
        "d.paddings.cookie, d.paddings.transport}\n"
        "\tif err := ValidateObfuscationResources(d.junk.count, d.junk.min, "
        "d.junk.max, paddings, specs); err != nil { return err }\n")
for field in ("init", "response", "cookie", "transport"):
    replace("uapi.go", f"\tdevice.paddings.{field}.Store(d.paddings.{field})\n", "")
replace("uapi.go",
        "\tdevice.headerProtection.key = d.headerProtectionKey\n\n\treturn nil",
        "\tdevice.headerProtection.key = d.headerProtectionKey\n"
        "\tdevice.obfuscation.Lock()\n"
        "\tdevice.paddings.init.Store(d.paddings.init)\n"
        "\tdevice.paddings.response.Store(d.paddings.response)\n"
        "\tdevice.paddings.cookie.Store(d.paddings.cookie)\n"
        "\tdevice.paddings.transport.Store(d.paddings.transport)\n"
        "\tdevice.junk.count.Store(d.junk.count)\n"
        "\tdevice.junk.min.Store(d.junk.min)\n"
        "\tdevice.junk.max.Store(d.junk.max)\n"
        "\tdevice.ipackets = d.ipackets\n"
        "\tdevice.obfuscation.Unlock()\n\n\treturn nil")
# IpcGet already owns ipcMutex, but a coherent read still needs the same lock.
replace("uapi.go",
        "\t\tif count := device.junk.count.Load(); count != 0 {",
        "\t\tdevice.obfuscation.RLock()\n"
        "\t\tif count := device.junk.count.Load(); count != 0 {")
replace("uapi.go",
        "\t\tif !device.headerProtection.key.IsZero() {",
        "\t\tdevice.obfuscation.RUnlock()\n"
        "\t\tif !device.headerProtection.key.IsZero() {")

# The public JunkPackets method must propagate invalid-state errors rather
# than silently omitting required camouflage. The handshake path uses one
# coherent snapshot for I/J/S1.
old_junk = """func (device *Device) JunkPackets() [][]byte {
	var bufs [][]byte

	min := device.junk.min.Load()
	max := device.junk.max.Load()

	for range device.junk.count.Load() {
		buf := make([]byte, min+fastrandn(max-min))
		rand.Read(buf)
		bufs = append(bufs, buf)
	}

	return bufs
}"""
replace("noise-protocol.go", old_junk,
        """func (device *Device) JunkPackets() ([][]byte, error) {
	device.obfuscation.RLock()
	defer device.obfuscation.RUnlock()
	count, min, max := device.junk.count.Load(), device.junk.min.Load(), device.junk.max.Load()
	if err := ValidateJunkPacketSettings(count, min, max); err != nil { return nil, err }
	return device.junkPacketsLocked(count, min, max), nil
}""")
replace("noise-protocol.go", '\t"crypto/rand"\n', "")
replace("noise-protocol.go",
        "return chacha20.NewUnauthenticatedCipher(device.headerProtection.key[:], salt)",
        """if len(salt) < HeaderCipherNonceSize {
		return nil, errors.New("header protection nonce too short")
	}
	return chacha20.NewUnauthenticatedCipher(device.headerProtection.key[:], salt[:HeaderCipherNonceSize])""")
assert texts["send.go"].count("crypt[:HeaderCipherNonceSize]") == 4, (
    "unknown send header-protection call sites"
)
texts["send.go"] = texts["send.go"].replace("crypt[:HeaderCipherNonceSize]", "crypt")
replace("send.go",
        """	var sendBuffer [][]byte

	for _, ipacket := range peer.device.ipackets {
		if ipacket != nil {
			buf := make([]byte, ipacket.ObfuscatedLen(0))
			ipacket.Obfuscate(buf, nil)
			sendBuffer = append(sendBuffer, buf)
		}
	}

	sendBuffer = append(sendBuffer, peer.device.JunkPackets()...)

	padding := int(peer.device.paddings.init.Load())""",
        """	sendBuffer, initialPadding, err := peer.device.prepareInitialObfuscation()
	if err != nil { return err }
	padding := int(initialPadding)""")

limits_go = r'''// SPDX-License-Identifier: MIT
package device

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
)

const (
	maxJunkCount uint32 = 64
	maxObfuscationPart uint32 = 4096
	maxJunkAggregate uint64 = 256 * 1024
	maxInitialAggregate uint32 = 5 * maxObfuscationPart
	maxInitialSpecBytes = 16 * 1024
)

var ErrObfuscationResourceBudget = errors.New("obfuscation resource budget exceeded")

// Jc=0 preserves ordinary WireGuard, including dormant Jmin/Jmax settings.
func ValidateJunkPacketSettings(count, min, max uint32) error {
	if count == 0 { return nil }
	if count > maxJunkCount || min > max || max > maxObfuscationPart ||
		uint64(count)*uint64(max) > maxJunkAggregate {
		return ErrObfuscationResourceBudget
	}
	return nil
}

// ValidateInitialPacketSpec checks the exact tags consumed by newObfChain.
// It runs before the tag builders and their unbounded Atoi-derived lengths.
func ValidateInitialPacketSpec(spec string) (uint32, error) {
	if len(spec) > maxInitialSpecBytes { return 0, ErrObfuscationResourceBudget }
	var total uint32
	remaining := spec
	for {
		start := strings.IndexByte(remaining, '<')
		if start < 0 { break } // newObfChain ignores inert text outside tags.
		remaining = remaining[start+1:]
		end := strings.IndexByte(remaining, '>')
		if end < 0 { return 0, ErrObfuscationResourceBudget }
		parts := strings.Fields(remaining[:end])
		remaining = remaining[end+1:]
		if len(parts) == 0 { return 0, ErrObfuscationResourceBudget }
		value := ""
		if len(parts) > 1 { value = parts[1] }
		var size uint32
		switch parts[0] {
		case "r", "rc", "rd", "dz":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 || n > int64(maxObfuscationPart) { return 0, ErrObfuscationResourceBudget }
			size = uint32(n)
		case "b":
			if value == "" { return 0, ErrObfuscationResourceBudget }
			encoded := strings.TrimPrefix(value, "0x")
			if len(encoded) == 0 || len(encoded)%2 != 0 || len(encoded)/2 > int(maxObfuscationPart) {
				return 0, ErrObfuscationResourceBudget
			}
			if _, err := hex.DecodeString(encoded); err != nil { return 0, ErrObfuscationResourceBudget }
			size = uint32(len(encoded) / 2)
		case "t":
			size = 4
		case "d", "ds":
		default:
			return 0, ErrObfuscationResourceBudget
		}
		if size > maxObfuscationPart-total { return 0, ErrObfuscationResourceBudget }
		total += size
	}
	return total, nil
}

func ValidateObfuscationResources(count, min, max uint32, paddings [4]uint32, specs [5]string) error {
	if err := ValidateJunkPacketSettings(count, min, max); err != nil { return err }
	for _, padding := range paddings {
		if padding > maxObfuscationPart { return ErrObfuscationResourceBudget }
	}
	var total uint32
	for _, spec := range specs {
		size, err := ValidateInitialPacketSpec(spec)
		if err != nil || size > maxInitialAggregate-total { return ErrObfuscationResourceBudget }
		total += size
	}
	return nil
}

// Preflight only the resource fields, using the effective final set values.
// Other UAPI mutations keep their existing semantics; this function ensures
// unsafe resource input and read failure cannot partially mutate the device.
func preflightObfuscationSet(lines []string, current *ipcSetDevice) error {
	count, min, max := current.junk.count, current.junk.min, current.junk.max
	headerKey := current.headerProtectionKey
	paddings := [4]uint32{current.paddings.init, current.paddings.response,
		current.paddings.cookie, current.paddings.transport}
	var specs [5]string
	for i, chain := range current.ipackets { if chain != nil { specs[i] = chain.Spec } }
	deviceFields := true
	for _, line := range lines {
		if line == "" { break }
		key, value, ok := strings.Cut(line, "=")
		if !ok { return ipcErrorf(ipc.IpcErrorProtocol, "UAPI line has no separator") }
		if key == "public_key" { deviceFields = false; continue }
		if !deviceFields { continue }
		switch key {
		case "jc", "jmin", "jmax":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil { return ipcErrorf(ipc.IpcErrorInvalid, "invalid junk parameter") }
			switch key { case "jc": count = uint32(n); case "jmin": min = uint32(n); case "jmax": max = uint32(n) }
		case "s1", "s2", "s3", "s4":
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil { return ipcErrorf(ipc.IpcErrorInvalid, "invalid padding parameter") }
			paddings[int(key[1]-'1')] = uint32(n)
		case "i1", "i2", "i3", "i4", "i5":
			if _, err := ValidateInitialPacketSpec(value); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "unsafe initial packet: %w", err)
			}
			specs[int(key[1]-'1')] = value
		case "header_protection_key":
			if err := headerKey.FromHex(value); err != nil {
				return ipcErrorf(ipc.IpcErrorInvalid, "invalid header protection key")
			}
		}
	}
	if err := ValidateObfuscationResources(count, min, max, paddings, specs); err != nil {
		return ipcErrorf(ipc.IpcErrorInvalid, "unsafe obfuscation resources: %w", err)
	}
	if !headerKey.IsZero() {
		for _, padding := range paddings {
			if padding < HeaderCipherNonceSize {
				return ipcErrorf(ipc.IpcErrorInvalid, "header protection padding is too short")
			}
		}
	}
	return nil
}

// Caller holds device.obfuscation.RLock and has validated the whole budget.
func (device *Device) junkPacketsLocked(count, min, max uint32) [][]byte {
	var bufs [][]byte
	for range count {
		buf := make([]byte, min+fastrandn(max-min))
		_, _ = rand.Read(buf)
		bufs = append(bufs, buf)
	}
	return bufs
}

func (device *Device) prepareInitialObfuscation() ([][]byte, uint32, error) {
	device.obfuscation.RLock()
	defer device.obfuscation.RUnlock()
	count, min, max := device.junk.count.Load(), device.junk.min.Load(), device.junk.max.Load()
	paddings := [4]uint32{device.paddings.init.Load(), device.paddings.response.Load(),
		device.paddings.cookie.Load(), device.paddings.transport.Load()}
	var specs [5]string
	for i, chain := range device.ipackets { if chain != nil { specs[i] = chain.Spec } }
	if err := ValidateObfuscationResources(count, min, max, paddings, specs); err != nil {
		return nil, 0, err
	}
	var bufs [][]byte
	for _, chain := range device.ipackets {
		if chain == nil { continue }
		length := chain.ObfuscatedLen(0)
		if length < 0 || length > int(maxObfuscationPart) { return nil, 0, ErrObfuscationResourceBudget }
		buf := make([]byte, length)
		chain.Obfuscate(buf, nil)
		bufs = append(bufs, buf)
	}
	bufs = append(bufs, device.junkPacketsLocked(count, min, max)...)
	return bufs, paddings[0], nil
}
'''
test_go = r'''// SPDX-License-Identifier: MIT
package device

import (
	"errors"
	"strings"
	"testing"
)

type interruptedPrimarySetReader struct { emitted bool }

func (r *interruptedPrimarySetReader) Read(p []byte) (int, error) {
	if !r.emitted {
		r.emitted = true
		return copy(p, []byte("replace_peers=true\njc=2\n")), nil
	}
	return 0, errors.New("synthetic read interruption")
}

func testResourceDevice() *Device {
	d := &Device{log: &Logger{DiscardLogf, DiscardLogf}}
	var header UintRange
	header.FromUint32(MessageInitiationType, MessageInitiationType); d.headers.init.Store(header)
	header.FromUint32(MessageResponseType, MessageResponseType); d.headers.response.Store(header)
	header.FromUint32(MessageCookieReplyType, MessageCookieReplyType); d.headers.cookie.Store(header)
	header.FromUint32(MessageTransportType, MessageTransportType); d.headers.transport.Store(header)
	return d
}

func TestPrimaryObfuscationResourceBudget(t *testing.T) {
	var zero [4]uint32
	var noInitial [5]string
	if err := ValidateObfuscationResources(0, 65535, 1, zero, noInitial); err != nil {
		t.Fatal("ordinary WG with Jc=0 must remain valid:", err)
	}
	valid := [5]string{"<r 40><t><ds>", "<b 0x0102><rc 3><rd 2><dz 1>"}
	if err := ValidateObfuscationResources(3, 40, 70, [4]uint32{20, 30, 0, 0}, valid); err != nil {
		t.Fatal("bounded AWG profile rejected:", err)
	}
	cases := []struct{name string; count, min, max uint32; specs [5]string}{
		{"reversed", 1, 100, 10, noInitial},
		{"high_count", 65, 10, 10, noInitial},
		{"large_size", 64, 4096, 4097, noInitial},
		{"large_padding", 0, 0, 0, noInitial},
		{"huge_initial", 0, 0, 0, [5]string{"<r 999999999>"}},
		{"negative_initial", 0, 0, 0, [5]string{"<dz -1>"}},
		{"large_bytes", 0, 0, 0, [5]string{"<b " + strings.Repeat("aa", 4097) + ">"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			padding := zero
			if tc.name == "large_padding" { padding[1] = 4097 }
			if err := ValidateObfuscationResources(tc.count, tc.min, tc.max, padding, tc.specs); err == nil {
				t.Fatal("unsafe profile accepted")
			}
		})
	}
}

func TestPrimaryUAPIStagesWholeObfuscationBeforeCommit(t *testing.T) {
	d := testResourceDevice()
	if err := d.IpcSetOperation(strings.NewReader("jc=1\njmin=40\njmax=70\ni1=<r 20>\n")); err != nil { t.Fatal(err) }
	if d.junk.count.Load() != 1 || d.ipackets[0] == nil { t.Fatal("valid profile was not committed") }
	if err := d.IpcSetOperation(strings.NewReader("jmax=90\njmin=50\n")); err != nil {
		t.Fatal("valid reordered update rejected:", err)
	}
	if d.junk.min.Load() != 50 || d.junk.max.Load() != 90 { t.Fatal("reordered update not committed") }
	bufs, padding, err := d.prepareInitialObfuscation()
	if err != nil || padding != 0 || len(bufs) != 2 || len(bufs[0]) != 20 ||
		len(bufs[1]) < 50 || len(bufs[1]) > 90 {
		t.Fatal("bounded snapshot did not retain I and J packets:", err)
	}
	for _, bad := range []string{"jc=65\n", "jmin=100\njmax=10\n",
		"jc=2\ni1=<r 999999999>\n", "i1=<r -1>\n"} {
		if err := d.IpcSetOperation(strings.NewReader(bad)); err == nil { t.Fatal("unsafe UAPI accepted") }
		if d.junk.count.Load() != 1 || d.junk.min.Load() != 50 ||
			d.junk.max.Load() != 90 || d.ipackets[0].Spec != "<r 20>" {
			t.Fatal("failed UAPI changed active obfuscation")
		}
	}
}

func TestPrimaryUnsafeSetDoesNotRemovePeers(t *testing.T) {
	d := testResourceDevice()
	d.peers.keyMap = map[NoisePublicKey]*Peer{NoisePublicKey{}: &Peer{}}
	if err := d.IpcSetOperation(strings.NewReader("replace_peers=true\njc=65\n")); err == nil {
		t.Fatal("unsafe resources accepted")
	}
	if len(d.peers.keyMap) != 1 || d.junk.count.Load() != 0 {
		t.Fatal("unsafe request changed peers or junk count before rejection")
	}
	key := strings.Repeat("01", 32)
	if err := d.IpcSetOperation(strings.NewReader(
		"replace_peers=true\nheader_protection_key=" + key + "\ns1=0\n")); err == nil {
		t.Fatal("short header padding accepted")
	}
	if len(d.peers.keyMap) != 1 || !d.headerProtection.key.IsZero() {
		t.Fatal("invalid header resources changed peers or key")
	}
}

func TestPrimaryInterruptedSetDoesNotCommit(t *testing.T) {
	d := testResourceDevice()
	d.peers.keyMap = map[NoisePublicKey]*Peer{NoisePublicKey{}: &Peer{}}
	if err := d.IpcSetOperation(&interruptedPrimarySetReader{}); err == nil {
		t.Fatal("interrupted input accepted")
	}
	if len(d.peers.keyMap) != 1 || d.junk.count.Load() != 0 {
		t.Fatal("read-failed request changed peers or junk count")
	}
}

func TestPrimaryOrdinaryWGNoObfuscationPadding(t *testing.T) {
	d := testResourceDevice()
	bufs, padding, err := d.prepareInitialObfuscation()
	if err != nil || padding != 0 || len(bufs) != 0 {
		t.Fatal("ordinary WG snapshot changed:", err)
	}
	cipher, err := d.HeaderProtectionCipher(nil)
	if err != nil || cipher != nil { t.Fatal("ordinary WG needs no header nonce:", err) }
	d.headerProtection.key[0] = 1
	if _, err := d.HeaderProtectionCipher(nil); err == nil {
		t.Fatal("enabled header protection accepted missing nonce")
	}
}
'''

for name, path in paths.items():
    path.write_text(texts[name], encoding="utf-8", newline="\n")
new_source.write_text(limits_go, encoding="utf-8", newline="\n")
new_test.write_text(test_go, encoding="utf-8", newline="\n")
subprocess.run(["gofmt", "-w", *(str(path) for path in
                (*paths.values(), new_source, new_test))], check=True)
after_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (*paths.values(), new_source, new_test)}
print(json.dumps({"layout": "module-root" if module_layout else "vendored-app-root",
                  "before": before_hashes, "after": after_hashes}, sort_keys=True))
