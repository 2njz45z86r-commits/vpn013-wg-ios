// SPDX-License-Identifier: MIT
package r013

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const NativeTrialLabel = "Три дня теста бесплатно"
const NativeTrialDuration int64 = 259200

var nativeRenewalPattern = regexp.MustCompile(`^https://t\.me/vpn013_com_bot\?start=trial_[A-Za-z0-9_-]{43}$`)

type NativeTrialMetadata struct {
	DurationSeconds int64  `json:"durationSeconds"`
	RenewalURL      string `json:"renewalURL"`
}

func (m NativeTrialMetadata) Validate() error {
	if m.DurationSeconds != NativeTrialDuration || !nativeRenewalPattern.MatchString(m.RenewalURL) {
		return ErrDocument
	}
	return nil
}

type NativeTrialInfo struct {
	Schema          int    `json:"schema"`
	Kind            string `json:"kind"`
	App             string `json:"app"`
	OrderID         string `json:"orderID"`
	State           string `json:"state"`
	IssuedAt        int64  `json:"issuedAt"`
	ExpiresAt       int64  `json:"expiresAt"`
	ServerTime      int64  `json:"serverTime"`
	DurationSeconds int64  `json:"durationSeconds"`
	IsTrial         bool   `json:"isTrial"`
	RenewalURL      string `json:"renewalURL"`
	Ticket          string `json:"ticket,omitempty"`
}

func (v NativeTrialInfo) Validate(previous *NativeTrialInfo) error {
	if v.Schema != 1 || v.Kind != "vpn013-native-trial" || v.App != "vpn013-wg" || !idPattern.MatchString(v.OrderID) ||
		v.IssuedAt <= 0 || v.ExpiresAt <= 0 || v.ServerTime <= 0 || v.DurationSeconds != NativeTrialDuration ||
		v.IsTrial && v.ExpiresAt-v.IssuedAt != NativeTrialDuration*1000 || !nativeRenewalPattern.MatchString(v.RenewalURL) ||
		v.Ticket != "" && !tokenPattern.MatchString(v.Ticket) {
		return ErrDocument
	}
	switch v.State {
	case "provisioning", "active", "revoking", "revoked", "expired":
	default:
		return ErrDocument
	}
	if previous != nil && (previous.OrderID != v.OrderID || previous.RenewalURL != v.RenewalURL) {
		return ErrDocument
	}
	return nil
}

type NativeTrialState struct {
	RequestID    string           `json:"requestID"`
	Ticket       string           `json:"ticket,omitempty"`
	Info         *NativeTrialInfo `json:"info,omitempty"`
	ServerOffset int64            `json:"serverOffset"`
}

func NewNativeTrialState() (*NativeTrialState, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return &NativeTrialState{RequestID: base64.RawURLEncoding.EncodeToString(raw)}, nil
}
func nativePost(ctx context.Context, action string, fields map[string]string, ticket string, client *http.Client) ([]byte, error) {
	if action != "create" && action != "info" && action != "file" || ticket != "" && !tokenPattern.MatchString(ticket) {
		return nil, ErrDocument
	}
	body, err := json.Marshal(fields)
	if err != nil || len(body) > 2048 {
		return nil, ErrDocument
	}
	limit := int64(32768)
	kind := "application/json"
	if action == "file" {
		limit = 8 * MaxDocument
		kind = "application/zip"
	}
	for _, origin := range []string{"https://connect.vpn555.shop:8443", "https://connect.vpn555.shop:8444"} {
		req, e := http.NewRequestWithContext(ctx, "POST", origin+"/client/trial/awg/"+action, bytes.NewReader(body))
		if e != nil {
			return nil, ErrDocument
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", kind)
		if ticket != "" {
			req.Header.Set("Authorization", "Bearer "+ticket)
		}
		resp, e := client.Do(req)
		if e != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		func() {
			defer resp.Body.Close()
			statusOK := resp.StatusCode == 200 || action == "create" && resp.StatusCode == 202
			media, _, parseErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
			if !statusOK || parseErr != nil || media != kind || resp.ContentLength > limit {
				err = ErrDocument
				return
			}
			body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
			if int64(len(body)) > limit {
				err = ErrDocument
			}
		}()
		if err != nil {
			return nil, ErrDocument
		}
		return body, nil
	}
	return nil, errors.New("Тест пока недоступен. Повторное нажатие продолжит ту же заявку.")
}
func nativeClient() *http.Client {
	return &http.Client{Timeout: 100 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func NativeTrialStatus(ctx context.Context, state *NativeTrialState) (*NativeTrialInfo, error) {
	if state == nil || !tokenPattern.MatchString(state.RequestID) || state.Ticket != "" && !tokenPattern.MatchString(state.Ticket) {
		return nil, ErrDocument
	}
	action := "info"
	fields := map[string]string{}
	if state.Ticket == "" {
		action = "create"
		fields = map[string]string{"requestID": state.RequestID, "platform": "windows"}
	}
	data, err := nativePost(ctx, action, fields, state.Ticket, nativeClient())
	if err != nil {
		return nil, err
	}
	var info NativeTrialInfo
	if json.Unmarshal(data, &info) != nil || info.Validate(state.Info) != nil || state.Ticket == "" && !tokenPattern.MatchString(info.Ticket) {
		return nil, ErrDocument
	}
	return &info, nil
}
func NativeTrialZIP(ctx context.Context, state *NativeTrialState) ([]byte, error) {
	if state == nil || !tokenPattern.MatchString(state.Ticket) {
		return nil, ErrDocument
	}
	return nativePost(ctx, "file", map[string]string{"platform": "windows"}, state.Ticket, nativeClient())
}
func ReadNativeTrialZIP(data []byte, info *NativeTrialInfo) (*Archive, error) {
	if len(data) > 8*MaxDocument || info == nil || info.Validate(nil) != nil {
		return nil, ErrDocument
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(reader.File) > 60 {
		return nil, ErrDocument
	}
	found := false
	for _, file := range reader.File {
		if strings.ContainsAny(file.Name, "/\\") || strings.Contains(file.Name, "..") {
			return nil, ErrDocument
		}
		if file.Name != "VPN013-Access.json" {
			continue
		}
		if found || file.UncompressedSize64 > MaxDocument {
			return nil, ErrDocument
		}
		found = true
		stream, e := file.Open()
		if e != nil {
			return nil, ErrDocument
		}
		raw, e := io.ReadAll(io.LimitReader(stream, MaxDocument+1))
		stream.Close()
		if e != nil || len(raw) > MaxDocument {
			return nil, ErrDocument
		}
		var metadata struct {
			Trial *NativeTrialMetadata `json:"trial"`
		}
		if json.Unmarshal(raw, &metadata) != nil || metadata.Trial == nil || metadata.Trial.Validate() != nil || metadata.Trial.RenewalURL != info.RenewalURL {
			return nil, ErrDocument
		}
	}
	parsed, err := ReadArchive(reader)
	if err != nil || !found || parsed.Access == nil || parsed.Access.Snapshot.OrderID != info.OrderID || parsed.Access.Snapshot.Expiry != info.ExpiresAt || len(parsed.Profiles) != len(parsed.Access.Snapshot.Servers) {
		return nil, ErrDocument
	}
	return parsed, nil // Existing managed importer additionally matches exact canonical configs.
}
