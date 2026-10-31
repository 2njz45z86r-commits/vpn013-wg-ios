//go:build ignore

// SPDX-License-Identifier: MIT
// Disposable hosted fixture. No provider/customer credentials or external TLS target.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	rproto "github.com/xtls/reality"
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/vless/inbound"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/splithttp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
)

func instance(object any) *core.Instance {
	raw, err := json.Marshal(object)
	if err != nil {
		panic("fixture config encoding")
	}
	config, err := serial.LoadJSONConfig(bytes.NewReader(raw))
	if err != nil {
		panic("fixture config validation")
	}
	server, err := core.New(config)
	if err != nil {
		panic("fixture core creation")
	}
	if server.Start() != nil {
		panic("fixture core start")
	}
	return server
}
func main() {
	self := len(os.Args) == 2 && os.Args[1] == "--self-test"
	host := "198.18.0.1"
	if self {
		host = "127.0.0.1"
	}
	echo, err := net.Listen("tcp", host+":0")
	if err != nil {
		panic("fixture echo listener")
	}
	defer echo.Close()
	echoPort := echo.Addr().(*net.TCPAddr).Port
	nonce := uuid.NewString()
	httpServer := &http.Server{ReadHeaderTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+nonce {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, nonce)
	})}
	defer httpServer.Close()
	go httpServer.Serve(echo)
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("fixture tls key")
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, 1024)}}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &private.PublicKey, private)
	if err != nil {
		panic("fixture cert")
	}
	cover, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, CurvePreferences: []tls.CurveID{tls.X25519}})
	if err != nil {
		panic("fixture tls listener")
	}
	defer cover.Close()
	go func() {
		for {
			conn, e := cover.Accept()
			if e != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				handshakeError := conn.(*tls.Conn).Handshake()
				if handshakeError != nil {
					return
				}
				_, _ = conn.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0})
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	// This pinned core's server adapter predates the REALITY post-handshake
	// detector initialization required by its module. Initialize only this
	// disposable local cover using the module's own detector, never TLS bypass.
	rproto.DetectPostHandshakeRecordsLens(&rproto.Config{Type: "tcp", Dest: cover.Addr().String(), ServerNames: map[string]bool{"localhost": true}})
	readyDeadline := time.Now().Add(4 * time.Second)
	for {
		value, _ := rproto.GlobalPostHandshakeRecordsLens.Load(cover.Addr().String() + " localhost 2")
		if _, ok := value.([]int); ok {
			break
		}
		if time.Now().After(readyDeadline) {
			panic("fixture post-handshake detector not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("fixture reality key")
	}
	user := uuid.NewString()
	short := "ab12"
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("fixture port")
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	xreserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("fixture xhttp port")
	}
	xport := xreserve.Addr().(*net.TCPAddr).Port
	_ = reserve.Close()
	_ = xreserve.Close()
	inbound := func(network string, listenPort int) any {
		stream := map[string]any{"network": network, "security": "reality", "realitySettings": map[string]any{"show": false, "dest": cover.Addr().String(), "serverNames": []string{"localhost"}, "privateKey": base64.RawURLEncoding.EncodeToString(key.Bytes()), "shortIds": []string{short}}}
		if network == "xhttp" {
			stream["xhttpSettings"] = map[string]any{"path": "/native-xhttp", "mode": "stream-one", "xPaddingBytes": "16-32"}
		}
		return map[string]any{"listen": "127.0.0.1", "port": listenPort, "protocol": "vless", "settings": map[string]any{"clients": []any{map[string]any{"id": user}}, "decryption": "none"}, "streamSettings": stream}
	}
	server := instance(map[string]any{"log": map[string]any{"loglevel": "none"}, "inbounds": []any{inbound("tcp", port), inbound("xhttp", xport)}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{host + "/32"}, "network": "tcp", "port": fmt.Sprint(echoPort)}, map[string]any{"action": "allow", "network": "tcp", "port": "443"}, map[string]any{"action": "allow", "ip": []string{"1.1.1.1/32"}, "network": "udp", "port": "53"}, map[string]any{"action": "block"}}}}}})
	defer server.Close()
	endpoint := "10.0.2.2"
	if self {
		endpoint = "127.0.0.1"
	}
	uri := fmt.Sprintf("vless://%s@%s:%d?security=reality&type=tcp&sni=localhost&fp=chrome&pbk=%s&sid=%s#NativeReality", user, endpoint, port, base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), short)
	// These non-default options must survive semantic import and reach the real
	// XHTTP core; the nonce exchange below is independent of UI/service flags.
	extra := map[string]any{"xPaddingBytes": "16-32", "xmux": map[string]any{"maxConnections": 1, "cMaxLifetimeMs": 0}, "scMaxBufferedPosts": 8}
	extraJSON, _ := json.Marshal(extra)
	xhttpURI := fmt.Sprintf("vless://%s@%s:%d?security=reality&type=xhttp&sni=localhost&fp=chrome&pbk=%s&sid=%s&mode=stream-one&path=%%2Fnative-xhttp&extra=%s#NativeXHTTP", user, endpoint, xport, base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), short, url.QueryEscape(string(extraJSON)))
	if self {
		for _, transport := range []struct {
			network string
			port    int
		}{{"tcp", port}, {"xhttp", xport}} {
			stream := map[string]any{"network": transport.network, "security": "reality", "realitySettings": map[string]any{"show": false, "serverName": "localhost", "fingerprint": "chrome", "publicKey": base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), "shortId": short}}
			if transport.network == "xhttp" {
				stream["xhttpSettings"] = map[string]any{"path": "/native-xhttp", "mode": "stream-one", "xPaddingBytes": "16-32", "xmux": map[string]any{"maxConnections": 1}}
			}
			client := instance(map[string]any{"log": map[string]any{"loglevel": "none"}, "outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": endpoint, "port": transport.port, "users": []any{map[string]any{"id": user, "encryption": "none"}}}}}, "streamSettings": stream}}})
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			conn, err := core.Dial(ctx, client, xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(echoPort)))
			if err != nil {
				panic("fixture client dial")
			}
			defer conn.Close()
			time.AfterFunc(8*time.Second, func() { _ = conn.Close() })
			_, err = fmt.Fprintf(conn, "GET /%s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", nonce)
			if err != nil {
				panic("fixture client request")
			}
			response, err := io.ReadAll(io.LimitReader(conn, 4096))
			if err != nil || !strings.Contains(string(response), nonce) {
				panic(fmt.Sprintf("fixture REALITY traffic failed err=%v bytes=%d", err, len(response)))
			}
			fmt.Printf("Disposable REALITY/VLESS %s fixture nonce exchange passed\n", transport.network)
			_ = conn.Close()
			_ = client.Close()
		}
		return
	}
	folder := os.Getenv("RUNNER_TEMP")
	if folder == "" {
		panic("hosted temporary directory required")
	}
	data, _ := json.Marshal(map[string]any{"uri": uri, "xhttpURI": xhttpURI, "host": host, "port": echoPort, "nonce": nonce})
	if os.WriteFile(filepath.Join(folder, "r013-proxy-fixture.json"), data, 0600) != nil {
		panic("fixture output")
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
