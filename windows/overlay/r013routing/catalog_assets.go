// SPDX-License-Identifier: MIT
package r013routing

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"sync"
)

// These are inert, exact owner-provided resources. Decode validates UI/rules.
//
//go:embed catalog-ui.json
var embeddedCatalogUI []byte

//go:embed catalog-rules.json
var embeddedCatalogRules []byte

//go:embed catalog-groups.json
var embeddedCatalogGroups []byte
var embeddedOnce sync.Once
var embeddedCatalog *ServiceCatalog
var embeddedErr error

func OwnerCatalog() (*ServiceCatalog, error) {
	embeddedOnce.Do(func() {
		if fmt.Sprintf("%x", sha256.Sum256(embeddedCatalogGroups)) != "a88d52da61ab4e596bb6050843bf11619148de40235a00a8162c660aba1ab882" {
			embeddedErr = errors.New("catalog group hash mismatch")
			return
		}
		embeddedCatalog, embeddedErr = DecodeServiceCatalog(embeddedCatalogUI, embeddedCatalogRules)
	})
	return embeddedCatalog, embeddedErr
}
