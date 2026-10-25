// SPDX-License-Identifier: MIT
// Package r013prepare resolves only a bounded immutable member copy. Original
// domain, keys, DNS, addresses and AWG fields remain in the vault unchanged.
package r013prepare

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	probe "github.com/amnezia-vpn/amneziawg-windows-client/r013probe"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013vault"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

var ErrPreparation = errors.New("candidate endpoint or immutable configuration is not confirmed")

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type Roles struct{ Physical4, Physical6 uint32 }
type Member struct {
	original conf.Config
	uapi     string
	endpoint netip.AddrPort
	source   netip.Addr
	identity string
}

func (m *Member) Original() (conf.Config, error) {
	if m == nil {
		return conf.Config{}, ErrPreparation
	}
	return r013vault.CopyConfig(m.original)
}

// UAPI is sensitive memory-only data. It must never be logged, serialized or
// sent to a remote service. The endpoint is already numeric: ToUAPI cannot
// launch a second uncancellable hostname lookup later under a mutation fence.
func (m *Member) UAPI() string {
	if m == nil {
		return ""
	}
	return m.uapi
}
func (m *Member) Endpoint() netip.AddrPort {
	if m == nil {
		return netip.AddrPort{}
	}
	return m.endpoint
}
func (m *Member) Source() netip.Addr {
	if m == nil {
		return netip.Addr{}
	}
	return m.source
}
func (m *Member) Identity() string {
	if m == nil {
		return ""
	}
	return m.identity
}

// Identity examines only the client/server keys, before resolving any endpoint.
// It shares the exact clamped public digest used by ActiveGuard; aliases cannot
// start DNS/UDP just because their names, endpoints or private-key clamp bits
// differ. No key is retained in the returned identifier.
func Identity(c conf.Config) (string, error) {
	if c.Interface.PrivateKey.IsZero() || len(c.Peers) != 1 || c.Peers[0].PublicKey.IsZero() {
		return "", ErrPreparation
	}
	return probe.PublicIdentityDigest(fmt.Sprintf("private_key=%s\npublic_key=%s\n", c.Interface.PrivateKey.HexString(), c.Peers[0].PublicKey.HexString()))
}

func Prepare(parent context.Context, original conf.Config, activeIdentity string, roles Roles, resolver Resolver) (*Member, error) {
	return prepareMember(parent, original, activeIdentity, roles, resolver, true)
}

// PreparePrimary resolves an immutable replacement for a fenced PRIMARY change.
// It launches no UDP. An active identity may be retried only after the service
// owner has genuinely retired the old engine. Candidate probes must still use
// Prepare AND ActiveGuard, which rejects every running-identity alias before UDP.
func PreparePrimary(parent context.Context, original conf.Config, roles Roles, resolver Resolver) (*Member, error) {
	return prepareMember(parent, original, "", roles, resolver, false)
}

func prepareMember(parent context.Context, original conf.Config, activeIdentity string, roles Roles, resolver Resolver, denyActive bool) (*Member, error) {
	if parent == nil || parent.Err() != nil || roles.Physical4 == 0 || resolver == nil {
		return nil, ErrPreparation
	}
	// Bound before cloning / constructing the UAPI; no network occurs here.
	wire, err := json.Marshal(original)
	if err != nil || len(wire) > r013.MaxDocument {
		return nil, ErrPreparation
	}
	c, err := r013vault.CopyConfig(original)
	if err != nil || r013.ValidateCandidates([]conf.Config{c}) != nil || !r013vault.EligibleForComparison(c) {
		return nil, ErrPreparation
	}
	identity, err := Identity(c)
	if err != nil {
		return nil, ErrPreparation
	}
	if denyActive {
		active, activeError := hex.DecodeString(activeIdentity)
		if activeError != nil || len(active) != 32 || strings.ToLower(activeIdentity) != activeIdentity {
			return nil, ErrPreparation
		}
		if identity == activeIdentity {
			return nil, probe.ErrActiveIdentity
		}
	}
	var source netip.Addr
	for _, a := range c.Interface.Addresses {
		if ip, ok := netip.AddrFromSlice(a.IP.To4()); ok && !ip.IsUnspecified() && !ip.IsMulticast() {
			source = ip.Unmap()
			break
		}
	}
	if !source.IsValid() {
		return nil, ErrPreparation
	}
	host := c.Peers[0].Endpoint.Host
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "\x00\r\n") {
		return nil, ErrPreparation
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	var addresses []netip.Addr
	if ip, e := netip.ParseAddr(host); e == nil {
		addresses = []netip.Addr{ip}
	} else {
		addresses, err = resolver.LookupNetIP(ctx, "ip", host)
		if err != nil || ctx.Err() != nil {
			return nil, ErrPreparation
		}
	}
	if len(addresses) < 1 || len(addresses) > 16 {
		return nil, ErrPreparation
	}
	var chosen netip.Addr
	for _, ip := range addresses {
		if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		ip = ip.Unmap()
		if (ip.Is4() && roles.Physical4 != 0) || (ip.Is6() && roles.Physical6 != 0) {
			chosen = ip
			break
		}
	}
	if !chosen.IsValid() || ctx.Err() != nil {
		return nil, ErrPreparation
	}
	backend, err := r013vault.CopyConfig(c)
	if err != nil {
		return nil, ErrPreparation
	}
	backend.Peers[0].Endpoint.Host = chosen.String()
	uapi, err := backend.ToUAPI()
	if err != nil || len(uapi) > r013.MaxDocument || ctx.Err() != nil {
		return nil, ErrPreparation
	}
	return &Member{original: c, uapi: uapi, endpoint: netip.AddrPortFrom(chosen, c.Peers[0].Endpoint.Port), source: source, identity: identity}, nil
}

var _ Resolver = (*net.Resolver)(nil)
