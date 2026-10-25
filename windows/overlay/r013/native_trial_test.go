// SPDX-License-Identifier: MIT
package r013

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func nativeInfoFixture() NativeTrialInfo {
	return NativeTrialInfo{Schema: 1, Kind: "vpn013-native-trial", App: "vpn013-wg", OrderID: "012345abcdef", State: "active", IssuedAt: 1900000000000, ExpiresAt: 1900259200000, ServerTime: 1900000001000, DurationSeconds: NativeTrialDuration, IsTrial: true, RenewalURL: PurchaseURL + "?start=trial_" + strings.Repeat("C", 43)}
}
func TestNativeTrialInfoRejectsForeignOrChangedTerms(t *testing.T) {
	good := nativeInfoFixture()
	if good.Validate(nil) != nil {
		t.Fatal("valid72h rejected")
	}
	tests := []struct {
		name   string
		change func(*NativeTrialInfo)
	}{
		{"hour", func(v *NativeTrialInfo) { v.DurationSeconds = 3600 }},
		{"deadline", func(v *NativeTrialInfo) { v.ExpiresAt++ }},
		{"state", func(v *NativeTrialInfo) { v.State = "paid" }},
		{"otherbot", func(v *NativeTrialInfo) {
			v.RenewalURL = strings.Replace(v.RenewalURL, "vpn013_com_bot", "foreign_bot", 1)
		}},
		{"insecure", func(v *NativeTrialInfo) { v.RenewalURL = strings.Replace(v.RenewalURL, "https", "http", 1) }},
		{"query", func(v *NativeTrialInfo) { v.RenewalURL += "&extra=1" }},
		{"fragment", func(v *NativeTrialInfo) { v.RenewalURL += "#x" }},
		{"foreignorder", func(v *NativeTrialInfo) { v.OrderID = "ffffffffffff" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			v := good
			test.change(&v)
			if v.Validate(&good) == nil {
				t.Fatal("accepted invalid info")
			}
		})
	}
	renewed := good
	renewed.IsTrial = false
	renewed.ExpiresAt += 30 * 86400000
	if renewed.Validate(&good) != nil {
		t.Fatal("paid extension must preserve personal renewal")
	}
}
func TestNativeTrialNonceUsesIndependentStrongRandomBytes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		v, err := NewNativeTrialState()
		if err != nil || !tokenPattern.MatchString(v.RequestID) || seen[v.RequestID] {
			t.Fatal("invalid/repeated request nonce")
		}
		seen[v.RequestID] = true
	}
}

type nativeRoundTripper func(*http.Request) (*http.Response, error)

func (f nativeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestNativeTrialHTTPUsesFixedHTTPSBearerAndBounds(t *testing.T) {
	for _, test := range []struct {
		name, kind   string
		status, size int
		good         bool
	}{
		{"valid", "application/json", 202, 2, true},
		{"redirect", "application/json", 302, 2, false},
		{"denied", "application/json", 403, 2, false},
		{"wrongmime", "text/plain", 200, 2, false},
		{"oversize", "application/json", 200, 32769, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: nativeRoundTripper(func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != "https://connect.vpn555.shop:8443/client/trial/awg/create" || req.Method != "POST" || req.Header.Get("Authorization") != "Bearer "+strings.Repeat("A", 43) {
					t.Fatal("unsafe URL/method/role")
				}
				body, _ := io.ReadAll(req.Body)
				if string(body) != "{}" {
					t.Fatal("unexpected body")
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{"Content-Type": []string{test.kind}}, Body: io.NopCloser(strings.NewReader(strings.Repeat(" ", test.size))), ContentLength: int64(test.size)}, nil
			})}
			_, err := nativePost(context.Background(), "create", map[string]string{}, strings.Repeat("A", 43), client)
			if (err == nil) != test.good {
				t.Fatalf("response accepted=%v", err == nil)
			}
		})
	}
	if _, err := nativePost(context.Background(), "../admin", nil, "", nativeClient()); err == nil {
		t.Fatal("unsafe action accepted")
	}
}
func TestNativeTrialZIPRequiresFullBoundRootBundle(t *testing.T) {
	info := nativeInfoFixture()
	server := Server{ID: "alpha", Name: "Alpha", Config: "synthetic-fixture"}
	snapshot := Snapshot{Schema: 1, Kind: "vpn013-awg", OrderID: info.OrderID, Expiry: info.ExpiresAt, Complete: true, Servers: []Server{server}, Revision: Digest("alpha\nAlpha\nsynthetic-fixture\n")}
	for _, test := range []struct {
		name                     string
		traversal, omit, foreign bool
	}{
		{name: "complete"}, {name: "traversal", traversal: true}, {name: "missingconfig", omit: true}, {name: "foreignrenewal", foreign: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var data bytes.Buffer
			z := zip.NewWriter(&data)
			renewal := info.RenewalURL
			if test.foreign {
				renewal = PurchaseURL + "?start=trial_" + strings.Repeat("D", 43)
			}
			doc := map[string]any{"schema": 1, "kind": "vpn013-access", "capability": strings.Repeat("B", 43), "snapshot": snapshot, "trial": NativeTrialMetadata{NativeTrialDuration, renewal}}
			raw, _ := json.Marshal(doc)
			entry, _ := z.Create("VPN013-Access.json")
			entry.Write(raw)
			if !test.omit {
				name := "Alpha.conf"
				if test.traversal {
					name = "../Alpha.conf"
				}
				entry, _ = z.Create(name)
				entry.Write([]byte(server.Config))
			}
			z.Close()
			_, err := ReadNativeTrialZIP(data.Bytes(), &info)
			if (err == nil) != (test.name == "complete") {
				t.Fatalf("bundle accepted=%v", err == nil)
			}
		})
	}
}
