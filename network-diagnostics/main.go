// A disposable standard WireGuard client entirely in userspace. It creates no
// operating-system interface, routes, service, installed driver or persistent key.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type peer struct {
	Public    string   `json:"publicKey"`
	PSK       string   `json:"preSharedKey"`
	Endpoint  string   `json:"endpoint"`
	Allowed   []string `json:"allowedIPs"`
	KeepAlive int      `json:"keepAlive"`
}
type profile struct {
	Secret   string   `json:"secretKey"`
	NoKernel bool     `json:"noKernelTun"`
	Address  []string `json:"address"`
	Peers    []peer   `json:"peers"`
}
type check struct {
	URL     string `json:"url"`
	Status  int    `json:"status,omitempty"`
	Bytes   int    `json:"bytes,omitempty"`
	Egress  string `json:"egress_ipv4,omitempty"`
	Failed  bool   `json:"failed"`
	Failure string `json:"failure,omitempty"`
}
type report struct {
	Engine            string  `json:"engine"`
	Endpoint          string  `json:"endpoint_domain"`
	Handshake         bool    `json:"authenticated_handshake"`
	Traffic           bool    `json:"traffic_verified"`
	LastHandshake     int64   `json:"last_handshake_unix"`
	Received          int64   `json:"received_bytes"`
	Sent              int64   `json:"sent_bytes"`
	ProbeMTU          int     `json:"probe_internal_mtu"`
	HostRoutesChanged bool    `json:"host_routes_changed"`
	Checks            []check `json:"checks"`
}

func key(value string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(data) != 32 {
		return "", errors.New("invalid disposable key")
	}
	return hex.EncodeToString(data), nil
}

func run() error {
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil || len(data) > 8192 {
		return errors.New("invalid disposable input")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	var cfg profile
	if dec.Decode(&cfg) != nil || dec.Decode(new(any)) != io.EOF {
		return errors.New("invalid input object")
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Endpoint != "de1.vpn013.com:8443" || !cfg.NoKernel || len(cfg.Address) != 2 || cfg.Peers[0].KeepAlive != 0 {
		return errors.New("fixture outside approved scope")
	}
	priv, err := key(cfg.Secret)
	if err != nil {
		return err
	}
	pub, err := key(cfg.Peers[0].Public)
	if err != nil {
		return err
	}
	psk, err := key(cfg.Peers[0].PSK)
	if err != nil {
		return err
	}
	var addresses []netip.Addr
	for _, text := range cfg.Address {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || (text != "10.253.252.2/32" && text != "fd13:8443::2/128") {
			return errors.New("unexpected fixture address")
		}
		addresses = append(addresses, prefix.Addr())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "de1.vpn013.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "81.90.25.23" {
		return errors.New("endpoint DNS changed")
	}
	tun, network, err := netstack.CreateNetTUN(addresses, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, 1420)
	if err != nil {
		return errors.New("userspace network initialization failed")
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	// The local listen port is omitted: the library requests an ephemeral port.
	uapi := "private_key=" + priv + "\npublic_key=" + pub + "\npreshared_key=" + psk + "\nendpoint=" + net.JoinHostPort(ips[0].String(), "8443") + "\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=0\n"
	if dev.IpcSet(uapi) != nil || dev.Up() != nil {
		return errors.New("WireGuard device initialization failed")
	}
	// This control exercises IPv4 explicitly; IPv6 is a separate acceptance.
	transport := &http.Transport{DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) {
		return network.DialContext(ctx, "tcp4", address)
	}, ResponseHeaderTimeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 18 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	result := report{Engine: "official wireguard-go / independent userspace netstack", Endpoint: "de1.vpn013.com:8443", ProbeMTU: 1420}
	for _, url := range []string{"https://www.gstatic.com/generate_204", "https://api.ipify.org?format=json"} {
		record := check{URL: url, Failed: true}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		if err != nil {
			record.Failure = fmt.Sprintf("%T", err)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				record.Failure = "network_timeout"
			}
		}
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1025))
			resp.Body.Close()
			record.Status = resp.StatusCode
			record.Bytes = len(body)
			if readErr == nil && len(body) <= 1024 && resp.TLS != nil && len(resp.TLS.VerifiedChains) > 0 {
				record.Failed = false
				if strings.Contains(url, "api.ipify.org") {
					var ip struct {
						IP string `json:"ip"`
					}
					if json.Unmarshal(body, &ip) == nil && ip.IP == "81.90.25.23" && resp.StatusCode == 200 {
						record.Egress = ip.IP
						result.Traffic = true
					}
				}
			}
		}
		result.Checks = append(result.Checks, record)
	}
	stats, err := dev.IpcGet()
	if err == nil {
		// IpcGet contains keys: only these three numeric fields may leave RAM.
		for _, line := range strings.Split(stats, "\n") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			number, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				continue
			}
			switch parts[0] {
			case "last_handshake_time_sec":
				result.LastHandshake = number
			case "rx_bytes":
				result.Received = number
			case "tx_bytes":
				result.Sent = number
			}
		}
	}
	result.Handshake = result.LastHandshake > time.Now().Add(-2*time.Minute).Unix()
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "Disposable WireGuard check failed; no credentials printed")
		os.Exit(1)
	}
}
