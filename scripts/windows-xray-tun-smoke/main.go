// Disposable Windows runner only: test a single synthetic route, not VPN013.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const user = "00000000-0000-4000-8000-000000000001"
const adapter = "VPN013-CI-Isolated"
const target = "198.18.34.56"
const marker = "VPN013-synthetic-windows-tun-success"

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
func certificate(dir string) (string, string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", "", err
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return "", "", "", err
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		return "", "", "", err
	}
	sum := sha256.Sum256(der)
	return certPath, keyPath, hex.EncodeToString(sum[:]), nil
}
func start(exe, config string) (*exec.Cmd, error) {
	cmd := exec.Command(exe, "run", "-config", config)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}
func stop(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}
func waitUntil(deadline time.Duration, condition func() bool) bool {
	until := time.Now().Add(deadline)
	for time.Now().Before(until) {
		if condition() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}
func run() error {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("VPN013_DISPOSABLE_TUN_SMOKE") != "yes" || len(os.Args) != 2 {
		return errors.New("disposable Windows GitHub runner required")
	}
	exe, err := filepath.Abs(os.Args[1])
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "vpn013-ci-tun-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	cert, key, pin, err := certificate(dir)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	echoPort := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, marker) })}
	defer server.Close()
	go server.Serve(listener)
	vlessPort := freePort()
	inbound := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": vlessPort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": user}}, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": cert, "keyFile": key}}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"redirect": fmt.Sprintf("127.0.0.1:%d", echoPort), "finalRules": []any{map[string]any{"action": "allow", "network": "tcp", "port": fmt.Sprint(echoPort), "ip": []string{"127.0.0.1/32"}}}}}}}
	outbound := map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{map[string]any{"protocol": "tun", "settings": map[string]any{"name": adapter, "mtu": 1280, "gateway": []string{"198.18.0.1/32"}, "autoSystemRoutingTable": []string{target + "/32"}, "autoOutboundsInterface": ""}}}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": vlessPort, "users": []any{map[string]any{"id": user, "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "localhost", "pinnedPeerCertSha256": pin}}}}}
	a, b := filepath.Join(dir, "server.json"), filepath.Join(dir, "client.json")
	if err = writeJSON(a, inbound); err != nil {
		return err
	}
	if err = writeJSON(b, outbound); err != nil {
		return err
	}
	srv, err := start(exe, a)
	if err != nil {
		return err
	}
	defer stop(srv)
	if !waitUntil(15*time.Second, func() bool {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", vlessPort), time.Second)
		if e != nil {
			return false
		}
		c.Close()
		return true
	}) {
		return errors.New("synthetic VLESS endpoint did not start")
	}
	client, err := start(exe, b)
	if err != nil {
		return err
	}
	defer stop(client)
	if !waitUntil(20*time.Second, func() bool { _, e := net.InterfaceByName(adapter); return e == nil }) {
		return errors.New("test TUN adapter did not start")
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	verified := false
	for attempt := 0; attempt < 8; attempt++ {
		response, e := httpClient.Get(fmt.Sprintf("http://%s:%d/", target, echoPort))
		if e == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1024))
			response.Body.Close()
			if readErr == nil && response.StatusCode == 200 && string(body) == marker {
				verified = true
				break
			}
		}
		time.Sleep(time.Second)
	}
	if !verified {
		return errors.New("synthetic HTTP payload did not traverse single-route TUN and VLESS")
	}
	fmt.Println("synthetic_windows_tun_vless_http_payload_ok")
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
