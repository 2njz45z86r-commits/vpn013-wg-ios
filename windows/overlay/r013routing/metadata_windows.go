// SPDX-License-Identifier: MIT
package r013routing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"golang.org/x/sys/windows"
)

const serviceMetadataName = "VPN013-Service-Routing-v1"
const serviceMetadataFile = "r013-service-routing.dat"

type ProfilePolicy struct {
	Name         string           `json:"name"`
	SourceDigest string           `json:"sourceDigest"`
	Selection    ServiceSelection `json:"selection"`
}
type ServicePolicies struct {
	Version  int             `json:"version"`
	Profiles []ProfilePolicy `json:"profiles"`
}

func ProfileSourceDigest(c *conf.Config) string {
	h := sha256.Sum256([]byte(c.ToWgQuick()))
	return hex.EncodeToString(h[:])
}

// Auto's saved working configuration can change at handover. Its stable
// source is the exact encrypted vault revision, not the current seed file.
func PolicyTargetDigest(c *conf.Config) (string, error) {
	if c == nil {
		return "", errors.New("missing profile")
	}
	if strings.EqualFold(c.Name, r013.AutoName) {
		vault, err := r013vault.Load()
		if err != nil {
			return "", err
		}
		if _, _, err = vault.WorkingMember(*c); err != nil {
			return "", err
		}
		return vault.Revision(), nil
	}
	return ProfileSourceDigest(c), nil
}
func validateServicePolicies(doc ServicePolicies) error {
	if doc.Version != 1 || len(doc.Profiles) > 90 {
		return errors.New("service metadata version or bound")
	}
	cat, err := OwnerCatalog()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, p := range doc.Profiles {
		n := strings.ToLower(p.Name)
		d, e := hex.DecodeString(p.SourceDigest)
		if !conf.TunnelNameIsValid(p.Name) || seen[n] || e != nil || len(d) != sha256.Size || p.SourceDigest != strings.ToLower(p.SourceDigest) {
			return errors.New("invalid service profile binding")
		}
		seen[n] = true
		if _, err = cat.Resolve(p.Selection); err != nil {
			return err
		}
	}
	return nil
}
func servicePolicyPath() (string, error) {
	root, err := conf.RootDirectory(true)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, serviceMetadataFile), nil
}

// LoadServicePolicies is called in the SYSTEM manager or tunnel service. The
// Data directory is ACL-protected by conf.RootDirectory; contents use DPAPI.
func LoadServicePolicies() (ServicePolicies, error) {
	empty := ServicePolicies{Version: 1}
	path, err := servicePolicyPath()
	if err != nil {
		return empty, err
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
		return empty, errors.New("invalid protected service metadata")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 2*1024*1024+1))
	if err != nil {
		return empty, err
	}
	if len(raw) > 2*1024*1024 {
		return empty, errors.New("protected service metadata too large")
	}
	raw, err = dpapi.Decrypt(raw, serviceMetadataName)
	if err != nil {
		return empty, err
	}
	var doc ServicePolicies
	if err = catalogJSON(raw, &doc); err != nil {
		return empty, err
	}
	if err = validateServicePolicies(doc); err != nil {
		return empty, err
	}
	return doc, nil
}

// SaveServicePolicies requires the manager's authorization and global policy
// mutex; validate all explicit targets and tunnel states before calling it.
func SaveServicePolicies(doc ServicePolicies) error {
	if err := validateServicePolicies(doc); err != nil {
		return err
	}
	path, err := servicePolicyPath()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if len(raw) > 2*1024*1024 {
		return errors.New("service metadata too large")
	}
	raw, err = dpapi.Encrypt(raw, serviceMetadataName)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".r013-services-*.pending")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func (doc ServicePolicies) ForProfile(c *conf.Config) (ServiceSelection, error) {
	if c == nil {
		return ServiceSelection{}, errors.New("missing service profile")
	}
	for _, p := range doc.Profiles {
		if strings.EqualFold(p.Name, c.Name) {
			if p.Selection.EffectiveMode() != ServicesUnchanged {
				digest, err := PolicyTargetDigest(c)
				if err != nil || p.SourceDigest != digest {
					return ServiceSelection{}, fmt.Errorf("Настройки сервисов профиля устарели. Примените их заново.")
				}
			}
			return p.Selection, nil
		}
	}
	return ServiceSelection{}, nil
}

// ValidateProfileForServicePolicy preflights without changing a profile. Only
// a single-peer full IPv4 tunnel is supported; IPv6 routes are left untouched.
func ValidateProfileForServicePolicy(c *conf.Config, selection ServiceSelection) error {
	cat, err := OwnerCatalog()
	if err != nil {
		return err
	}
	plan, err := cat.Resolve(selection)
	if err != nil || plan == nil {
		return err
	}
	if c == nil || c.Interface.TableOff || len(c.Peers) != 1 || c.Interface.PrivateKey.IsZero() || c.Peers[0].PublicKey.IsZero() || c.Peers[0].Endpoint.IsEmpty() || c.Peers[0].Endpoint.Port == 0 {
		return errors.New("Нужен профиль с одним сервером и полным IPv4-туннелем.")
	}
	v4routes, v4addresses := 0, 0
	for _, n := range c.Peers[0].AllowedIPs {
		if n.IP.To4() != nil {
			v4routes++
			// Match enableFirewall's exact default-route check, including
			// representation. A mapped address could otherwise leave WFP off.
			if n.Cidr != 0 || len(n.IP) != net.IPv4len || !n.IP.Equal(net.IPv4zero) {
				return errors.New("Нужен профиль с одним полным IPv4-маршрутом.")
			}
		}
	}
	for _, n := range c.Interface.Addresses {
		if n.IP.To4() != nil {
			v4addresses++
		}
	}
	if v4routes != 1 || v4addresses == 0 {
		return errors.New("Нужен профиль с одним полным IPv4-маршрутом.")
	}
	dns := make([]netip.Addr, 0, len(c.Interface.DNS))
	for _, ip := range c.Interface.DNS {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return errors.New("Некорректный DNS профиля.")
		}
		dns = append(dns, a.Unmap())
	}
	prepared, err := PrepareServiceRoutes(cat, selection, dns)
	if err != nil {
		return err
	}
	count := len(prepared.TunnelIPv4)
	hasIPv6 := false
	for _, n := range c.Interface.Addresses {
		if n.IP.To4() == nil && n.IP.To16() != nil {
			hasIPv6 = true
		}
	}
	if hasIPv6 {
		for _, n := range c.Peers[0].AllowedIPs {
			if n.IP.To4() != nil {
				continue
			}
			p, e := netip.ParsePrefix(n.String())
			if e != nil {
				return errors.New("Некорректный IPv6 маршрут профиля.")
			}
			parts, e := Exclude(p.Masked())
			if e != nil {
				return e
			}
			count += len(parts)
			if count > 40000 {
				return errors.New("Слишком много маршрутов. Уменьшите число выбранных сервисов.")
			}
		}
	}
	return nil
}
func ActivateProfileServicePolicy(c *conf.Config) error {
	doc, err := LoadServicePolicies()
	if err != nil {
		return err
	}
	selection, err := doc.ForProfile(c)
	if err != nil {
		return err
	}
	if selection.EffectiveMode() == ServicesUnchanged {
		activeService.Store(nil)
		return nil
	}
	if err = ValidateProfileForServicePolicy(c, selection); err != nil {
		return err
	}
	cat, err := OwnerCatalog()
	if err != nil {
		return err
	}
	dns := make([]netip.Addr, 0, len(c.Interface.DNS))
	for _, ip := range c.Interface.DNS {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return errors.New("Некорректный DNS профиля.")
		}
		dns = append(dns, a.Unmap())
	}
	var revision string
	if strings.EqualFold(c.Name, r013.AutoName) {
		revision, err = ValidateAutoServiceMembers(c, selection)
		if err != nil {
			return err
		}
	}
	if err = ActivateServicePolicy(cat, selection, dns); err != nil {
		return err
	}
	if revision != "" {
		p := *activeService.Load()
		p.vaultRevision = revision
		activeService.Store(&p)
	}
	return nil
}

func preparedForProfile(c *conf.Config, selection ServiceSelection) (*PreparedServiceRoutes, error) {
	if err := ValidateProfileForServicePolicy(c, selection); err != nil {
		return nil, err
	}
	cat, err := OwnerCatalog()
	if err != nil {
		return nil, err
	}
	dns := make([]netip.Addr, 0, len(c.Interface.DNS))
	for _, ip := range c.Interface.DNS {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, errors.New("Некорректный DNS профиля.")
		}
		dns = append(dns, a.Unmap())
	}
	return PrepareServiceRoutes(cat, selection, dns)
}

// An Auto policy belongs to the logical Auto profile, never to its manual
// members. Every candidate must produce exactly the same IPv4/WFP policy.
func ValidateAutoServiceMembers(current *conf.Config, selection ServiceSelection) (string, error) {
	vault, err := r013vault.Load()
	if err != nil {
		return "", err
	}
	if _, _, err = vault.WorkingMember(*current); err != nil {
		return "", err
	}
	if selection.EffectiveMode() == ServicesUnchanged {
		return vault.Revision(), nil
	}
	base, err := preparedForProfile(current, selection)
	if err != nil {
		return "", err
	}
	for i := 0; i < vault.Count(); i++ {
		member, _, e := vault.Member(i)
		if e != nil {
			return "", e
		}
		p, e := preparedForProfile(&member, selection)
		if e != nil {
			return "", e
		}
		if !reflect.DeepEqual(base, p) {
			return "", errors.New("Серверы Авто требуют несовместимых маршрутов или DNS. Выбор не применён.")
		}
	}
	return vault.Revision(), nil
}

// Called before probing and again before installing an Auto candidate. A
// replaced vault or changed effective policy never becomes the active policy.
func ValidateActiveAutoMember(c *conf.Config) error {
	active := activeService.Load()
	if active == nil || active.vaultRevision == "" {
		return nil
	}
	vault, err := r013vault.Load()
	if err != nil || vault.Revision() != active.vaultRevision {
		return errors.New("Состав Авто изменился; переключение остановлено.")
	}
	return ValidateActiveAutoRestore(c)
}

// Rollback may restore the already-running profile after an external vault
// replacement; retain its exact previous policy rather than dropping VPN.
func ValidateActiveAutoRestore(c *conf.Config) error {
	active := activeService.Load()
	if active == nil || active.vaultRevision == "" {
		return nil
	}
	p, err := preparedForProfile(c, active.selection)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(*p, active.routes) {
		return errors.New("Маршруты кандидата Авто отличаются; переключение остановлено.")
	}
	return nil
}
