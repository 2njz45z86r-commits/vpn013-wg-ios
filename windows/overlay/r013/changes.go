// SPDX-License-Identifier: MIT
package r013

// Expected is the digest of the previously imported canonical configuration.
// An empty digest means that no local profile may already occupy this name.
type Change struct {
	Name     string
	Expected string
	Config   string
	Remove   bool
	// AllowMissing restores/removes a locally deleted bound profile. Expected
	// still proves ownership of any retained Auto snapshot and existing file.
	AllowMissing bool
}
