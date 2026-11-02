package device

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVPN013AuthenticatedFallbackLocalTraffic(t *testing.T) {
	dir := os.Getenv("AWG_FIXTURES")
	if dir == "" {
		t.Fatal("synthetic fixture path is required")
	}
	var p struct {
		S  map[string]uint32    `json:"s"`
		H  map[string][2]uint32 `json:"h"`
		HP string               `json:"hp_key_hex"`
	}
	data, err := os.ReadFile(filepath.Join(dir, "params.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	options := []string{"s1", fmt.Sprint(p.S["initiation"]), "s2", fmt.Sprint(p.S["response"]), "s3", fmt.Sprint(p.S["cookie_reply"]), "s4", fmt.Sprint(p.S["transport"]),
		"h1", fmt.Sprintf("%d-%d", p.H["initiation"][0], p.H["initiation"][1]), "h2", fmt.Sprintf("%d-%d", p.H["response"][0], p.H["response"][1]),
		"h3", fmt.Sprintf("%d-%d", p.H["cookie_reply"][0], p.H["cookie_reply"][1]), "h4", fmt.Sprintf("%d-%d", p.H["transport"][0], p.H["transport"][1]),
		"random_trailers", "true", "content_padding_addition", "200"}
	for _, protect := range []bool{false, true} {
		name := "no-header-protection"
		if protect {
			name = "header-protection"
		}
		t.Run(name, func(t *testing.T) {
			profile := append([]string{}, options...)
			if protect {
				profile = append(profile, "header_protection_key", p.HP)
			}
			pair := genTestPair(t, true, profile...)
			for n := 0; n < 400; n++ {
				src, dst := pair[n%2], pair[(n+1)%2]
				msg := tuntest.Ping(dst.ip, src.ip)
				select {
				case src.tun.Outbound <- msg:
				case <-time.After(3 * time.Second):
					t.Fatalf("write timeout at %d", n)
				}
				select {
				case received := <-dst.tun.Inbound:
					if !bytes.Equal(received, msg) {
						t.Fatalf("changed packet at %d", n)
					}
				case <-time.After(3 * time.Second):
					t.Fatalf("lost packet at %d", n)
				}
			}
			t.Log("400 synthetic packets passed through two loopback peers")
		})
	}
}
