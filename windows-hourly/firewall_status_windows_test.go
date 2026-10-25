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
		name    string
		raw     func() uintptr
		wrapped func() error
	}{
		{"close", func() uintptr { r, _, _ := procFwpmEngineClose0.Call(0); return r }, func() error { return fwpmEngineClose0(0) }},
		{"commit", func() uintptr { r, _, _ := procFwpmTransactionCommit0.Call(0); return r }, func() error { return fwpmTransactionCommit0(0) }},
		{"begin", func() uintptr { r, _, _ := procFwpmTransactionBegin0.Call(0, 0); return r }, func() error { return fwpmTransactionBegin0(0, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status := tc.raw()
			if status == 0 {
				t.Fatal("invalid handle unexpectedly succeeded")
			}
			var code syscall.Errno
			if !errors.As(tc.wrapped(), &code) || uintptr(code) != status {
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
