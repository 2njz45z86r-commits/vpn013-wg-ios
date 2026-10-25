// SPDX-License-Identifier: MIT
package r013

import (
	"testing"
	"time"
)

func TestSnapshotActiveUsesServerMilliseconds(t *testing.T) {
	now := time.Date(2026, time.October, 25, 14, 0, 0, 500_000_000, time.UTC)
	for _, test := range []struct {
		name   string
		expiry int64
		active bool
	}{
		{"future", now.Add(time.Hour).UnixMilli(), true},
		{"one-millisecond-left", now.UnixMilli() + 1, true},
		{"exact-boundary", now.UnixMilli(), false},
		{"one-millisecond-expired", now.UnixMilli() - 1, false},
		{"yesterday", now.Add(-24 * time.Hour).UnixMilli(), false},
		{"seconds-are-not-the-protocol", now.Add(time.Hour).Unix(), false},
		{"zero", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := (Snapshot{Expiry: test.expiry}).Active(now); got != test.active {
				t.Fatalf("Active() = %v; want %v for millisecond expiry", got, test.active)
			}
		})
	}
	if (Snapshot{Expiry: now.UnixMilli()}).Active(now.In(time.FixedZone("Moscow", 3*60*60))) {
		t.Fatal("The same expiry instant must not depend on the local time zone")
	}
}
