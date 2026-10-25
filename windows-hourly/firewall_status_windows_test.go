// SPDX-License-Identifier: MIT
package firewall

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestWFPStatusUsesReturnedDWORDAndRejectsInvalidSession(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" {
		t.Fatal("disposable native CI required")
	}
	// These documented invalid-session calls do not change any WFP object.
	// Compare with the real return DWORD, independent of thread LastError.
	for _, tc := range []struct {
		name             string
		raw              func() uintptr
		wrapped          func() error
		rejectZeroHandle bool
	}{
		{"close", func() uintptr { r, _, _ := procFwpmEngineClose0.Call(0); return r }, func() error { return fwpmEngineClose0(0) }, false},
		{"commit", func() uintptr { r, _, _ := procFwpmTransactionCommit0.Call(0); return r }, func() error { return fwpmTransactionCommit0(0) }, true},
		{"begin", func() uintptr { r, _, _ := procFwpmTransactionBegin0.Call(0, 0); return r }, func() error { return fwpmTransactionBegin0(0, 0) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.raw()
			if status == 0 && tc.rejectZeroHandle {
				t.Fatal("invalid handle unexpectedly succeeded")
			}
			// This Windows build accepts Close(NULL) as idempotent success.
			// Preserve the actual SDK status; do not invent a required failure.
			wrapped := tc.wrapped()
			if status == 0 {
				if wrapped != nil {
					t.Fatal("successful native return was replaced by LastError")
				}
				return
			}
			var code syscall.Errno
			if !errors.As(wrapped, &code) || uintptr(code) != status {
				t.Fatal("WFP return status was hidden or replaced with LastError")
			}
		})
	}
	if VerifyFirewall() == nil {
		t.Fatal("missing policy accepted as active")
	}
	if ReplaceFirewall(0, false, []net.IP{{1, 2}}) == nil {
		t.Fatal("invalid DNS accepted")
	}
}
