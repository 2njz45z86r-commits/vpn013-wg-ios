// SPDX-License-Identifier: MIT
package r013

import "testing"

func TestInstalledCatalogBuildIsNotAnotherUpdate(t *testing.T) {
	if CurrentBuild != 9 {
		t.Fatalf("Windows1.5.6 catalog build must be9, got%d", CurrentBuild)
	}
	for _, test := range []struct {
		name, version string
		build         int
		newer         bool
	}{
		{"installed", "1.5.6", 9, false},
		{"older-build", "1.5.6", 8, false},
		{"next-build", "1.5.6", 10, true},
		{"older-version", "1.5.2", 99, false},
		{"next-version", "1.5.7", 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := (Release{Version: test.version, Build: test.build}).Newer("1.5.6", CurrentBuild); got != test.newer {
				t.Fatalf("catalog version=%s build=%d newer=%v, want%v", test.version, test.build, got, test.newer)
			}
		})
	}
}
