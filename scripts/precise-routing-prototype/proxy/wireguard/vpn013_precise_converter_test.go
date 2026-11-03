package wireguard

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVPN013PreciseConvertPreservesOnePeer(t *testing.T) {
	secret, public, psk := strings.Repeat("11", 32), strings.Repeat("22", 32), strings.Repeat("33", 32)
	input := "private_key=" + secret + "\nr013_legacy15=true\nj1=<b 0xa1a2><r 16>\nitime=1\ni1=<b 0xf1><r 16>\ns1=16\nlisten_port=0\nreplace_peers=true\npublic_key=" + public + "\npreshared_key=" + psk + "\nendpoint=127.0.0.1:8443\npersistent_keepalive_interval=10-11\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n"
	settings, err := VPN013ConvertUAPI(input, []string{"10.0.0.2/32", "fd13::2/128"}, 1280)
	if err != nil {
		t.Fatal("valid generated input rejected")
	}
	if settings.SecretKey != secret || settings.MTU != 1280 || len(settings.Address) != 2 || !settings.NoKernelTun || len(settings.Peers) != 1 {
		t.Fatal("interface changed")
	}
	peer := settings.Peers[0]
	if peer.PublicKey != public || peer.PreSharedKey != psk || peer.Endpoint != "127.0.0.1:8443" || peer.KeepAlive != "10-11" || len(peer.AllowedIPs) != 2 {
		t.Fatal("peer changed")
	}
	if settings.AWG["r013_legacy15"] != "true" || settings.AWG["j1"] != "<b 0xa1a2><r 16>" || settings.AWG["i1"] != "<b 0xf1><r 16>" {
		t.Fatal("obfuscation settings changed")
	}
	encoded, err := json.Marshal(settings)
	if err != nil || !strings.Contains(string(encoded), `"vpn013KeepAlive":"10-11"`) || !strings.Contains(string(encoded), `"vpn013AWG":`) {
		t.Fatal("wrong Xray settings encoding")
	}
}

func TestVPN013PreciseConvertRejectsLossAndInjection(t *testing.T) {
	key := strings.Repeat("12", 32)
	valid := "private_key=" + key + "\nreplace_peers=true\npublic_key=" + key + "\nendpoint=127.0.0.1:8443\nallowed_ip=0.0.0.0/0\n"
	cases := []string{
		"listen_port=12345\n" + valid,
		"private_key=secret-marker\n" + valid,
		valid + "unknown=secret-marker\n",
		valid + "public_key=" + key + "\n",
		strings.Replace(valid, "127.0.0.1:8443", "127.0.0.1:0", 1),
		strings.Replace(valid, "allowed_ip=0.0.0.0/0", "allowed_ip=not-a-prefix", 1),
		strings.Replace(valid, "private_key="+key, "private_key="+key+"\nprivate_key="+key, 1),
		strings.Replace(valid, "private_key="+key, "i1=ok\rsecret-marker\nprivate_key="+key, 1),
	}
	for i, input := range cases {
		result, err := VPN013ConvertUAPI(input, []string{"10.0.0.2/32"}, 1280)
		if err == nil || result.SecretKey != "" || strings.Contains(err.Error(), "secret-marker") || strings.Contains(err.Error(), key) {
			t.Fatalf("invalid case %d accepted or leaked", i)
		}
	}
}

func TestVPN013PreciseConvertRequiresExplicitNetworkInputs(t *testing.T) {
	key := strings.Repeat("12", 32)
	valid := "private_key=" + key + "\npublic_key=" + key + "\nendpoint=[::1]:8443\nallowed_ip=::/0\n"
	if _, err := VPN013ConvertUAPI(valid, nil, 1280); err == nil {
		t.Fatal("missing interface address accepted")
	}
	if _, err := VPN013ConvertUAPI(valid, []string{"10.0.0.2/32"}, 0); err == nil {
		t.Fatal("implicit MTU accepted")
	}
	if _, err := VPN013ConvertUAPI(valid, []string{"invalid"}, 1280); err == nil {
		t.Fatal("invalid address accepted")
	}
	if _, err := VPN013ConvertUAPI(valid, []string{"fd13::2/128"}, 1280); err != nil {
		t.Fatal("valid IPv6 profile rejected")
	}
}
