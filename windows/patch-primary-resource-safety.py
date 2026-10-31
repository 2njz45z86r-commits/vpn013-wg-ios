"""Fail closed on unsafe AWG resources before the Windows primary TUN starts.

The shared scripts/patch-primary-resource-safety.py must run first. This
Windows-only patch covers encrypted/saved profiles loaded by the tunnel
service; the shared device patch also protects direct runtime UAPI changes.
"""
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
path = root / "vendor/github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/service.go"
parser = root / "vendor/github.com/amnezia-vpn/amneziawg-windows/v3/conf/parser.go"
assert path.is_file() and path.resolve().is_relative_to(root)
assert parser.is_file() and parser.resolve().is_relative_to(root)
assert (root / "vendor/github.com/amnezia-vpn/amneziawg-go/v3/device/"
        "r013_resource_limits.go").is_file(), "shared AWG guard must run first"
source = path.read_text(encoding="utf-8")
parsed = parser.read_text(encoding="utf-8")
assert "r013gate.NewPrimaryDeviceSlot" in source, "unexpected Windows primary source"
anchor = """	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}"""
replacement = """	config, err = conf.LoadFromPath(service.Path)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}
	var primaryInitialSpecs [5]string
	for i := range primaryInitialSpecs {
		primaryInitialSpecs[i] = config.Interface.IPackets[fmt.Sprintf("i%d", i+1)]
	}
	err = device.ValidateObfuscationResources(
		uint32(config.Interface.JunkPacketCount),
		uint32(config.Interface.JunkPacketMinSize),
		uint32(config.Interface.JunkPacketMaxSize),
		[4]uint32{
			uint32(config.Interface.InitPacketJunkSize),
			uint32(config.Interface.ResponsePacketJunkSize),
			uint32(config.Interface.CookieReplyPacketJunkSize),
			uint32(config.Interface.TransportPacketJunkSize),
		},
		primaryInitialSpecs,
	)
	if err != nil {
		serviceError = services.ErrorLoadConfiguration
		return
	}"""
assert source.count(anchor) == 1, "unknown Windows profile-load path"
assert parsed.count('"golang.org/x/text/encoding/unicode"') == 1
parsed = parsed.replace('"golang.org/x/text/encoding/unicode"',
    '"golang.org/x/text/encoding/unicode"\n'
    '\t"github.com/amnezia-vpn/amneziawg-go/v3/device"', 1)
function_anchor = "func FromWgQuick(s string, name string) (*Config, error) {"
assert parsed.count(function_anchor) == 1
validator = """// validatePrimaryResourceBudget uses the same pure device limit as direct UAPI.
// No offending profile content is retained in the error.
func validatePrimaryResourceBudget(config *Config) error {
	var specs [5]string
	for i := range specs {
		specs[i] = config.Interface.IPackets[fmt.Sprintf("i%d", i+1)]
	}
	return device.ValidateObfuscationResources(
		uint32(config.Interface.JunkPacketCount),
		uint32(config.Interface.JunkPacketMinSize),
		uint32(config.Interface.JunkPacketMaxSize),
		[4]uint32{
			uint32(config.Interface.InitPacketJunkSize),
			uint32(config.Interface.ResponsePacketJunkSize),
			uint32(config.Interface.CookieReplyPacketJunkSize),
			uint32(config.Interface.TransportPacketJunkSize),
		},
		specs,
	)
}

"""
parsed = parsed.replace(function_anchor, validator + function_anchor, 1)
return_anchor = "\treturn &conf, nil"
assert parsed.count(return_anchor) == 2, "unknown parser return paths"
parsed = parsed.replace(return_anchor,
    "\tif err := validatePrimaryResourceBudget(&conf); err != nil { return nil, err }\n"
    + return_anchor)
path.write_text(source.replace(anchor, replacement, 1), encoding="utf-8", newline="\n")
parser.write_text(parsed, encoding="utf-8", newline="\n")
subprocess.run(["gofmt", "-w", str(path), str(parser)], check=True)
print("Windows primary resource guard staged before import persistence and TUN creation")
