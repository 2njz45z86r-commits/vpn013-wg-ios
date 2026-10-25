// SPDX-License-Identifier: MIT
package ui

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
)

// Only this test binary contains these synthetic operations. The production
// constructor is fixed to HTTPS, protected state and the real manager writer.
type nativeTrialFixture struct {
	info                                               r013.NativeTrialInfo
	state                                              *r013.NativeTrialState
	imports, downloads, creates, refreshes, remembered int
	bound                                              bool
	unsafe                                             bool
	configs                                            []string
}

func newNativeTrialFixture(t *testing.T) *nativeTrialFixture {
	now := time.Now().UnixMilli()
	f := &nativeTrialFixture{info: r013.NativeTrialInfo{Schema: 1, Kind: "vpn013-native-trial", App: "vpn013-wg", OrderID: "012345abcdef", State: "active", IssuedAt: now, ExpiresAt: now + 259200000, ServerTime: now, DurationSeconds: 259200, IsTrial: true, RenewalURL: r013.PurchaseURL + "?start=trial_" + strings.Repeat("C", 43), Ticket: strings.Repeat("A", 43)}}
	state, e := r013.NewNativeTrialState()
	if e != nil {
		t.Fatal(e)
	}
	f.state = state
	for i := 0; i < 3; i++ {
		key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(31 + i)}, 32))
		peer := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(71 + i)}, 32))
		f.configs = append(f.configs, "[Interface]\nPrivateKey = "+key+"\nAddress = 10.13.0.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = "+peer+"\nEndpoint = 192.0.2.1:51820\nAllowedIPs = 0.0.0.0/0\n")
	}
	return f
}
func (f *nativeTrialFixture) archive(t *testing.T) []byte {
	servers := []r013.Server{}
	var digest strings.Builder
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	for i, text := range f.configs {
		id := string(rune('a' + i))
		name := "Test-" + id
		servers = append(servers, r013.Server{ID: id, Name: name, Config: text})
		digest.WriteString(id + "\n" + name + "\n" + text + "\n")
		if f.unsafe {
			name = "../" + name
		}
		entry, e := z.Create(name + ".conf")
		if e != nil {
			t.Fatal(e)
		}
		entry.Write([]byte(text))
	}
	snapshot := r013.Snapshot{Schema: 1, Kind: "vpn013-awg", OrderID: f.info.OrderID, Expiry: f.info.ExpiresAt, Revision: r013.Digest(digest.String()), Complete: true, Servers: servers}
	doc := map[string]any{"schema": 1, "kind": "vpn013-access", "capability": strings.Repeat("B", 43), "snapshot": snapshot, "trial": r013.NativeTrialMetadata{DurationSeconds: 259200, RenewalURL: f.info.RenewalURL}}
	raw, _ := json.Marshal(doc)
	entry, _ := z.Create("VPN013-Access.json")
	entry.Write(raw)
	z.Close()
	return out.Bytes()
}
func (f *nativeTrialFixture) operations(t *testing.T) nativeTrialOperations {
	return nativeTrialOperations{
		load: func() (*r013.NativeTrialState, error) { copy := *f.state; return &copy, nil },
		save: func(v *r013.NativeTrialState) error { copy := *v; f.state = &copy; return nil },
		status: func(ctx context.Context, state *r013.NativeTrialState) (*r013.NativeTrialInfo, error) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if state.Ticket == "" {
				f.creates++
			}
			copy := f.info
			return &copy, nil
		},
		download: func(ctx context.Context, state *r013.NativeTrialState) ([]byte, error) {
			f.downloads++
			return f.archive(t), nil
		},
		bound:    func(string) (bool, error) { return f.bound, nil },
		refresh:  func(context.Context, string) (int, error) { f.refreshes++; return 1, nil },
		remember: func(*r013.NativeTrialInfo) error { f.remembered++; return nil },
		importArchive: func(a *r013.Archive) error {
			if len(a.Profiles) != 3 || a.Access == nil {
				return r013.ErrDocument
			}
			for _, profile := range a.Profiles {
				if _, e := canonical(profile.Config, profile.Name); e != nil {
					return e
				}
			}
			f.imports++
			f.bound = true
			return nil
		},
	}
}
func TestNativeTrialCompositorImportsFullZIPAndProtectsPendingTicket(t *testing.T) {
	f := newNativeTrialFixture(t)
	info, count, err := acquireNativeTrialWith(context.Background(), func() error { return nil }, f.operations(t))
	if err != nil || count != 3 || info.OrderID != f.info.OrderID || f.imports != 1 || f.downloads != 1 || f.creates != 1 || f.remembered != 1 {
		t.Fatalf("direct native import failed: %v", err)
	}
	state := clientState{Bindings: map[string]orderBinding{}, NativeTrial: f.state, NativeTrialBindings: map[string]r013.NativeTrialMetadata{info.OrderID: {DurationSeconds: 259200, RenewalURL: info.RenewalURL}}}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := dpapi.Encrypt(raw, "VPN013-client-state-v1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte(f.state.Ticket)) || bytes.Contains(encrypted, []byte(info.RenewalURL)) {
		t.Fatal("native capability is plaintext")
	}
	opened, err := dpapi.Decrypt(encrypted, "VPN013-client-state-v1")
	if err != nil {
		t.Fatal(err)
	}
	var restored clientState
	if json.Unmarshal(opened, &restored) != nil || restored.NativeTrial.Ticket != f.state.Ticket || restored.NativeTrialBindings[info.OrderID].RenewalURL != info.RenewalURL {
		t.Fatal("protected state did not round-trip")
	}
}
func TestNativeTrialRepeatAndPaidRenewalNeverReimportOrResetKeys(t *testing.T) {
	f := newNativeTrialFixture(t)
	operations := f.operations(t)
	_, _, err := acquireNativeTrialWith(context.Background(), func() error { return nil }, operations)
	if err != nil {
		t.Fatal(err)
	}
	before := append([]string{}, f.configs...)
	deadline := f.info.ExpiresAt
	_, _, err = acquireNativeTrialWith(context.Background(), func() error { return nil }, operations)
	if err != nil {
		t.Fatal(err)
	}
	f.info.IsTrial = false
	f.info.ExpiresAt += 30 * 86400000
	_, _, err = acquireNativeTrialWith(context.Background(), func() error { return nil }, operations)
	if err != nil || f.creates != 1 || f.imports != 1 || f.downloads != 1 || f.refreshes != 2 || deadline+30*86400000 != f.info.ExpiresAt || strings.Join(before, "") != strings.Join(f.configs, "") {
		t.Fatal("repeat/renewal changed original keys or imported again")
	}
}
func TestNativeTrialExpiredOrRevokedNeverDownloadsOrImports(t *testing.T) {
	for _, status := range []string{"expired", "revoked"} {
		t.Run(status, func(t *testing.T) {
			f := newNativeTrialFixture(t)
			f.info.State = status
			if status == "expired" {
				f.info.ServerTime = f.info.ExpiresAt + 1
			}
			info, _, err := acquireNativeTrialWith(context.Background(), func() error { return nil }, f.operations(t))
			if status == "expired" && (err != nil || info.RenewalURL != f.info.RenewalURL) {
				t.Fatal("personal expiry renewal missing")
			}
			if status == "revoked" && err == nil {
				t.Fatal("revoked access accepted")
			}
			if f.downloads != 0 || f.imports != 0 || f.remembered != 0 {
				t.Fatal("expired/revoked access mutated profiles")
			}
		})
	}
}
func TestNativeTrialUnsafeZIPNeverStartsManagedMutation(t *testing.T) {
	f := newNativeTrialFixture(t)
	f.unsafe = true
	commits := 0
	_, _, err := acquireNativeTrialWith(context.Background(), func() error { commits++; return nil }, f.operations(t))
	if err == nil || commits != 0 || f.imports != 0 || f.remembered != 0 {
		t.Fatal("unsafe archive reached profile writer")
	}
}
func TestNativeTrialCancellationRetainsTicketWithoutManagedMutation(t *testing.T) {
	f := newNativeTrialFixture(t)
	_, _, err := acquireNativeTrialWith(context.Background(), func() error { return context.Canceled }, f.operations(t))
	if !errors.Is(err, context.Canceled) || f.imports != 0 || f.remembered != 0 || f.state.Ticket == "" || f.creates != 1 {
		t.Fatal("cancel lost resumable ticket or wrote profiles")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = acquireNativeTrialWith(ctx, func() error { return nil }, f.operations(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled network operation continued")
	}
}
