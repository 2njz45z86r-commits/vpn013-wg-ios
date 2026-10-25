// SPDX-License-Identifier: MIT
package r013

import "testing"

func TestInstalledCatalogBuildIsNotAnotherUpdate(t *testing.T) {
	if CurrentBuild != 5 {
		t.Fatalf("Windows1.5.2 catalog build must be5, got%d", CurrentBuild)
	}
	for _, test := range []struct {
		name, version string
		build         int
		newer         bool
	}{
		{"installed", "1.5.2", 5, false},
		{"older-build", "1.5.2", 4, false},
		{"next-build", "1.5.2", 6, true},
		{"older-version", "1.5.1", 99, false},
		{"next-version", "1.5.3", 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := (Release{Version: test.version, Build: test.build}).Newer("1.5.2", CurrentBuild); got != test.newer {
				t.Fatalf("catalog version=%s build=%d newer=%v, want%v", test.version, test.build, got, test.newer)
			}
		})
	}
}
