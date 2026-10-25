// SPDX-License-Identifier: MIT
package r013

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const AutoName = "R013-Auto"
const MaxDocument = 1048576
const PurchaseURL = "https://t.me/vpn013_com_bot"
const SupportURL = "https://t.me/R013_Support"

var ErrDocument = errors.New("Документ обновления не прошёл проверку. Прежние конфигурации сохранены.")
var idPattern = regexp.MustCompile(`^[a-f0-9]{12}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var serverPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type Server struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Config string `json:"config"`
}
type Snapshot struct {
	Schema   int      `json:"schema"`
	Kind     string   `json:"kind"`
	OrderID  string   `json:"orderID"`
	Expiry   int64    `json:"expiry"`
	Revision string   `json:"revision"`
	Complete bool     `json:"complete"`
	Servers  []Server `json:"servers"`
}
type AccessDocument struct {
	Schema     int      `json:"schema"`
	Kind       string   `json:"kind"`
	Capability string   `json:"capability"`
	Snapshot   Snapshot `json:"snapshot"`
}

func Digest(text string) string { h := sha256.Sum256([]byte(text)); return hex.EncodeToString(h[:]) }
func (s Snapshot) Validate(order string) error {
	if s.Schema != 1 || s.Kind != "vpn013-awg" || !idPattern.MatchString(s.OrderID) || order != "" && order != s.OrderID || !s.Complete || len(s.Servers) < 1 || len(s.Servers) > 30 || !hashPattern.MatchString(s.Revision) || s.Expiry <= 0 {
		return ErrDocument
	}
	ids, names := map[string]bool{}, map[string]bool{}
	var roster strings.Builder
	for _, p := range s.Servers {
		if !serverPattern.MatchString(p.ID) || p.Name == "" || len([]rune(p.Name)) > 128 || len(p.Config) == 0 || len(p.Config) > 65536 || strings.ContainsFunc(p.Name, unicode.IsControl) || ids[p.ID] || names[p.Name] {
			return ErrDocument
		}
		ids[p.ID], names[p.Name] = true, true
		roster.WriteString(p.ID + "\n" + p.Name + "\n" + p.Config + "\n")
	}
	if Digest(roster.String()) != s.Revision {
		return ErrDocument
	}
	return nil
}
func DecodeAccess(data []byte) (*AccessDocument, error) {
	if len(data) > MaxDocument {
		return nil, ErrDocument
	}
	var d AccessDocument
	if json.Unmarshal(data, &d) != nil || d.Schema != 1 || d.Kind != "vpn013-access" || !tokenPattern.MatchString(d.Capability) || d.Snapshot.Validate("") != nil {
		return nil, ErrDocument
	}
	return &d, nil
}
// The shared order API encodes expiry as Unix milliseconds on every platform.
func (s Snapshot) Active(now time.Time) bool { return s.Expiry > now.UnixMilli() }

type Profile struct{ Name, Config string }
type Archive struct {
	Profiles []Profile
	Access   *AccessDocument
}

func ReadArchive(reader *zip.Reader) (*Archive, error) {
	if len(reader.File) > 128 {
		return nil, errors.New("Слишком много файлов в ZIP.")
	}
	result := new(Archive)
	preferred := ""
	var total uint64
	for _, f := range reader.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		if strings.HasPrefix(name, "/") || strings.Contains(name, "../") {
			return nil, ErrDocument
		}
		total += f.UncompressedSize64
		if total > 4*MaxDocument {
			return nil, ErrDocument
		}
		if strings.EqualFold(path.Ext(name), ".conf") {
			first := strings.ToLower(strings.Split(name, "/")[0])
			if first == "windows" {
				preferred = "windows"
			} else if first == "iphone" && preferred != "windows" {
				preferred = "iphone"
			}
		}
	}
	seen := map[string]string{}
	for _, f := range reader.File {
		name := strings.ReplaceAll(f.Name, "\\", "/")
		base := path.Base(name)
		manifest := strings.EqualFold(base, "VPN013-Access.json")
		if !manifest && !strings.EqualFold(path.Ext(name), ".conf") {
			continue
		}
		if !manifest && preferred != "" && strings.Contains(name, "/") && strings.ToLower(strings.Split(name, "/")[0]) != preferred {
			continue
		}
		limit := int64(65536)
		if manifest {
			limit = MaxDocument
		}
		if f.UncompressedSize64 > uint64(limit) {
			return nil, ErrDocument
		}
		stream, err := f.Open()
		if err != nil {
			return nil, ErrDocument
		}
		contents, err := io.ReadAll(io.LimitReader(stream, limit+1))
		stream.Close()
		if err != nil || len(contents) > int(limit) {
			return nil, ErrDocument
		}
		if manifest {
			if result.Access != nil {
				return nil, ErrDocument
			}
			result.Access, err = DecodeAccess(contents)
			if err != nil {
				return nil, err
			}
			continue
		}
		profileName := strings.TrimSuffix(base, path.Ext(base))
		key := strings.ToLower(profileName)
		normalized := strings.ReplaceAll(strings.TrimSpace(string(contents)), "\r\n", "\n")
		if old, ok := seen[key]; ok {
			if old != normalized {
				return nil, errors.New("В ZIP есть разные конфигурации с одинаковым именем.")
			}
			continue
		}
		seen[key] = normalized
		result.Profiles = append(result.Profiles, Profile{profileName, string(contents)})
		if len(result.Profiles) > 30 {
			return nil, errors.New("Поддерживается до 30 серверов в одном архиве.")
		}
	}
	if len(result.Profiles) == 0 {
		return nil, errors.New("В архиве нет конфигураций .conf.")
	}
	return result, nil
}
