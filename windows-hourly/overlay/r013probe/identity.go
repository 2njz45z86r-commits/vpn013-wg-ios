// SPDX-License-Identifier: MIT
package awgprobe

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// The caller must explicitly supply the actual running config, or a known idle
// state. Unknown active membership fails closed. Keys are never logged/stored.
type ActiveState struct {
	Known         bool
	Configuration string
}

var ErrActiveIdentity = errors.New("candidate has the active client/server identity")
var ErrUnknownActiveState = errors.New("current peer identity is not confirmed")
var ErrInvalidIdentity = errors.New("one unambiguous client/server identity is required")

// PublicIdentityDigest exposes only a digest of the clamped public client and
// server keys. It never returns, retains or serializes the private scalar.
func PublicIdentityDigest(configuration string) (string, error) {
	id, err := peerIdentity(configuration)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func peerIdentity(configuration string) ([32]byte, error) {
	var none [32]byte
	if len(configuration) == 0 || len(configuration) > 1_048_576 {
		return none, ErrInvalidIdentity
	}
	var private, server []byte
	for _, line := range strings.Split(configuration, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "private_key" && key != "public_key") {
			continue
		}
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != 32 || string(decoded) == string(make([]byte, 32)) {
			return none, ErrInvalidIdentity
		}
		if key == "private_key" {
			if private != nil {
				return none, ErrInvalidIdentity
			}
			private = decoded
		} else {
			if server != nil {
				return none, ErrInvalidIdentity
			}
			server = decoded
		}
	}
	if private == nil || server == nil {
		return none, ErrInvalidIdentity
	}
	client, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return none, ErrInvalidIdentity
	}
	// Compare the public identity: clamping makes several raw private scalar
	// encodings equivalent. Endpoint/name/PSK changes do not make an idle peer.
	return sha256.Sum256(append(client.PublicKey().Bytes(), server...)), nil
}
