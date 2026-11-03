package wireguard_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/wireguard"
)

// Exercise the actual experimental Xray config parser, not just JSON shape.
func TestVPN013PreciseConvertedSettingsParseInXray(t *testing.T) {
	key := strings.Repeat("11", 32)
	input := "private_key=" + key + "\ns1=16\nr013_legacy15=false\npublic_key=" + key + "\nendpoint=127.0.0.1:8443\npersistent_keepalive_interval=10-11\nallowed_ip=0.0.0.0/0\n"
	converted, err := wireguard.VPN013ConvertUAPI(input, []string{"10.0.0.2/32"}, 1280)
	if err != nil {
		t.Fatal("conversion failed")
	}
	encoded, err := json.Marshal(converted)
	if err != nil {
		t.Fatal("encoding failed")
	}
	parsed := conf.WireGuardConfig{IsClient: true}
	if json.Unmarshal(encoded, &parsed) != nil {
		t.Fatal("settings parse failed")
	}
	message, err := parsed.Build()
	if err != nil {
		t.Fatal("Xray rejected converted settings")
	}
	built, ok := message.(*wireguard.DeviceConfig)
	if !ok || built.Mtu != 1280 || len(built.Peers) != 1 || built.Peers[0].KeepAlive != "10-11" || built.Vpn013Awg["s1"] != "16" {
		t.Fatal("Xray changed converted values")
	}
}
