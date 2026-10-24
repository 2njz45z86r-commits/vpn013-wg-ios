// SPDX-License-Identifier: MIT
package r013

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

// ProfileNameLess preserves native ordinary ordering while pinning managed Auto.
func ProfileNameLess(left, right string) bool {
	if left == AutoName || right == AutoName {
		return left == AutoName && right != AutoName
	}
	return conf.TunnelNameIsLess(left, right)
}

type CurrentPingTarget struct {
	Host, Endpoint, Identity string
	StoredFallback           bool
}

// Auto's stored profile may be a seed rather than the active server. Only a
// manual profile may fall back to its own endpoint when statistics are missing.
// Keys and full configurations never leave this helper.
func CurrentTarget(name string, runtimeConfig, storedConfig *conf.Config) (CurrentPingTarget, error) {
	c, fallback := runtimeConfig, false
	if c == nil || len(c.Peers) != 1 || c.Peers[0].Endpoint.IsEmpty() {
		if name == AutoName {
			return CurrentPingTarget{}, errors.New("Нет свежих данных текущего сервера Авто")
		}
		c, fallback = storedConfig, true
	}
	if c == nil || len(c.Peers) != 1 || c.Peers[0].Endpoint.IsEmpty() {
		return CurrentPingTarget{}, errors.New("Адрес текущего сервера недоступен")
	}
	peer := c.Peers[0]
	digest := sha256.Sum256([]byte(name + "\x00" + c.Interface.PrivateKey.Public().String() + "\x00" + peer.PublicKey.String() + "\x00" + peer.Endpoint.String()))
	return CurrentPingTarget{peer.Endpoint.Host, peer.Endpoint.String(), hex.EncodeToString(digest[:]), fallback}, nil
}
