// SPDX-License-Identifier: MIT
package r013

import (
	"testing"

	"github.com/amnezia-vpn/amneziawg-windows-client/version"
)

func TestInstalledCatalogBuildIsNotAnotherUpdate(t *testing.T) {
	if CurrentBuild != 10 {
		t.Fatalf("Windows 1.5.7 catalog build must be 10, got %d", CurrentBuild)
	}
	if version.Number != "1.5.7" {
		t.Fatalf("unexpected Windows application version %s", version.Number)
	}
	for _, test := range []struct {
		name, version string
		build         int
		newer         bool
	}{
		{"installed", "1.5.7", 10, false},
		{"older-build", "1.5.7", 9, false},
		{"next-build", "1.5.7", 11, true},
		{"older-version", "1.5.2", 99, false},
		{"next-version", "1.5.8", 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := (Release{Version: test.version, Build: test.build}).Newer(version.Number, CurrentBuild); got != test.newer {
				t.Fatalf("catalog version=%s build=%d newer=%v, want%v", test.version, test.build, got, test.newer)
			}
		})
	}
	if !(Release{Version: "1.5.7", Build: 10}).Newer("1.5.6", 9) {
		t.Fatal("released 1.5.6 build 9 does not offer candidate 1.5.7 build 10")
	}
	if (Release{Version: "1.5.6", Build: 9}).Newer("1.5.7", 10) {
		t.Fatal("published 1.5.6 must not be offered as an update to 1.5.7")
	}
}
