// SPDX-License-Identifier: MIT
package r013

import "testing"

func TestInstalledCatalogBuildIsNotAnotherUpdate(t *testing.T) {
	if CurrentBuild != 6 {
		t.Fatalf("Windows1.5.3 catalog build must be6, got%d", CurrentBuild)
	}
	for _, test := range []struct {
		name, version string
		build         int
		newer         bool
	}{
		{"installed", "1.5.3", 6, false},
		{"older-build", "1.5.3", 5, false},
		{"next-build", "1.5.3", 7, true},
		{"older-version", "1.5.2", 99, false},
		{"next-version", "1.5.4", 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := (Release{Version: test.version, Build: test.build}).Newer("1.5.3", CurrentBuild); got != test.newer {
				t.Fatalf("catalog version=%s build=%d newer=%v, want%v", test.version, test.build, got, test.newer)
			}
		})
	}
}
