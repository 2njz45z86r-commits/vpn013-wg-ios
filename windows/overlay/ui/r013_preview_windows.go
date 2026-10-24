//go:build r013preview

// SPDX-License-Identifier: MIT
package ui

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/lxn/walk"
)

func EnableR013Preview() { r013Preview = true; IsAdmin = true }

func RunR013Preview() {
	runtime.LockOSThread()
	EnableR013Preview()
	window, err := NewManageTunnelsWindow()
	if err != nil {
		panic(err)
	}
	window.Show()
	if destination := os.Getenv("VPN013_PREVIEW_VERIFY"); destination != "" {
		// Only this separate preview build owns an in-memory fake manager.
		// The application build does not contain this entry point or fixture.
		go verifyR013Preview(window, destination)
	}
	window.Run()
	window.Dispose()
}

func verifyR013Preview(window *ManageTunnelsWindow, destination string) {
	scenario := os.Getenv("VPN013_PREVIEW_SCENARIO")
	checks := []string{}
	var failure string
	defer func() {
		data, _ := json.MarshalIndent(map[string]any{"scenario": scenario, "checks": checks, "passed": failure == "", "failure": failure, "syntheticVPN": true, "actualLoopbackEcho": scenario != "auto-no-stats"}, "", "  ")
		if os.WriteFile(destination, data, 0600) != nil {
			failure = "Could not write verification report"
		}
		window.Synchronize(func() {
			if failure != "" {
				walk.App().Exit(1)
			} else {
				walk.App().Exit(0)
			}
		})
	}()
	deadline := time.Now().Add(15 * time.Second)
	ready := false
	for !ready && time.Now().Before(deadline) {
		window.Synchronize(func() { ready = window.currentCard.current.active })
		if !ready {
			time.Sleep(30 * time.Millisecond)
		}
	}
	if !ready {
		failure = "Current fixture did not become active"
		return
	}
	window.Synchronize(func() {
		model := window.tunnelsPage.listView.model
		if len(model.tunnels) == 0 || model.tunnels[0].Name != r013.AutoName {
			failure = "Auto not first"
			return
		}
		model.Sort(0, walk.SortDescending)
		if model.tunnels[0].Name != r013.AutoName {
			failure = "Header sorting moved Auto"
			return
		}
		checks = append(checks, "Auto first with valid + prefix and descending header sort")
		window.tunnelsPage.listView.selectTunnel("Germany")
		if window.currentCard.current.name == "Germany" {
			failure = "Selection replaced actual active card"
			return
		}
		checks = append(checks, "Selected inactive profile does not replace active card")
		if scenario == "auto-no-stats" {
			if window.currentCard.button.Enabled() || window.currentCard.current.target.Host != "" {
				failure = "Auto used stored seed without runtime"
				return
			}
			checks = append(checks, "Missing Auto runtime refuses seed endpoint")
			return
		}
		if !window.currentCard.button.Enabled() {
			failure = "Active current ping button disabled"
			return
		}
		if scenario == "manual-no-stats" && !window.currentCard.current.target.StoredFallback {
			failure = "Manual statistics fallback missing"
			return
		}
		window.currentCard.ping()
	})
	if failure != "" || scenario == "auto-no-stats" {
		return
	}
	complete := false
	for !complete && time.Now().Before(deadline) {
		window.Synchronize(func() { complete = window.currentCard.pingCancel == nil })
		if !complete {
			time.Sleep(30 * time.Millisecond)
		}
	}
	window.Synchronize(func() {
		text := window.currentCard.result.Text()
		if !complete || !strings.Contains(text, "мс") {
			failure = fmt.Sprintf("Actual loopback current ping did not complete: %s", text)
			return
		}
		checks = append(checks, "Current button performs real OS loopback ICMP and displays milliseconds")
		old := window.currentCard.current
		changed := old
		changed.target.Identity = "different-test-session"
		changed.target.Endpoint = "127.0.0.2:51821"
		window.currentCard.apply(changed, window.currentCard.revision.Load())
		if window.currentCard.result.Text() != "Пинг адреса · —" {
			failure = "Old result retained after identity change"
			return
		}
		checks = append(checks, "Changed active peer clears preceding ping")
		window.currentCard.apply(r013CurrentSnapshot{detail: "Preview disconnected"}, window.currentCard.revision.Load())
		if window.currentCard.button.Enabled() {
			failure = "Disconnected card retained ping button"
			return
		}
		checks = append(checks, "Disconnected session disables current ping")
	})
}
