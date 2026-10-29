// SPDX-License-Identifier: MIT
package r013proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
)

func TestRealTLSVLESSUsesProtectedSocketAndTransfersBytes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 18)
		if _, err = io.ReadFull(conn, header); err != nil {
			served <- err
			return
		}
		if header[0] != 0 || !bytes.Equal(header[1:17], make([]byte, 16)) {
			served <- io.ErrUnexpectedEOF
			return
		}
		if _, err = io.CopyN(io.Discard, conn, int64(header[17])); err != nil {
			served <- err
			return
		}
		destination := make([]byte, 4)
		if _, err = io.ReadFull(conn, destination); err != nil {
			served <- err
			return
		}
		if destination[0] != 1 || destination[3] != 1 {
			served <- io.ErrUnexpectedEOF
			return
		}
		if _, err = io.CopyN(io.Discard, conn, 4); err != nil {
			served <- err
			return
		}
		payload := make([]byte, 32)
		if _, err = io.ReadFull(conn, payload); err != nil {
			served <- err
			return
		}
		_, err = conn.Write(append([]byte{0, 0}, payload...))
		served <- err
	}()
	var protected atomic.Int32
	route := NewRoute(func(uintptr) bool { protected.Add(1); return true })
	defer route.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	object := map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": "127.0.0.1", "port": port, "users": []any{map[string]any{"id": "00000000-0000-0000-0000-000000000000", "encryption": "none"}}}}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{"serverName": "localhost", "allowInsecure": false, "certificates": []any{map[string]any{"usage": "verify", "certificate": strings.Split(strings.TrimSpace(string(certPEM)), "\n")}}}}}}}
	raw, _ := json.Marshal(object)
	config, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	instance, err := core.NewWithContext(route.Context(ctx), config)
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	if err = instance.Start(); err != nil {
		t.Fatal(err)
	}
	conn, err := core.Dial(route.Context(ctx), instance, xnet.TCPDestination(xnet.ParseAddress("198.18.0.1"), 9000))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte{0x59}, 32)
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) || protected.Load() != 1 {
		t.Fatal("traffic did not use the owned protected transport")
	}
	if err = <-served; err != nil {
		t.Fatal(err)
	}
}
