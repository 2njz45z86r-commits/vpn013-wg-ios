//go:build r013preview

// SPDX-License-Identifier: MIT
package ui

import (
	"encoding/json"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/version"
	"github.com/lxn/walk"
	"github.com/lxn/win"
)

// This audit seam exists only in the separately tagged in-memory preview.
var R013PreviewPowerAudit func() (starts, stops int, lastStart, lastStop string)

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
	echoVerified := false
	// Walk Synchronize queues work; a test must wait for actual UI completion.
	// A hung UI fails the external CI process timeout, never a partial pass.
	syncUI := func(fn func()) {
		done := make(chan struct{})
		window.Synchronize(func() { defer close(done); fn() })
		<-done
	}
	defer func() {
		minimum := 5
		if scenario == "update-offer" {
			minimum = 6
		}
		if scenario == "auto-no-stats" {
			minimum = 3
		}
		if scenario == "power" {
			minimum = 10
		}
		if len(checks) < minimum && failure == "" {
			failure = "Required UI checks did not execute"
		}
		data, _ := json.MarshalIndent(map[string]any{"scenario": scenario, "checks": checks, "passed": failure == "", "failure": failure, "syntheticVPN": true, "actualLoopbackEcho": echoVerified}, "", "  ")
		if os.WriteFile(destination, data, 0600) != nil {
			failure = "Could not write verification report"
		}
		syncUI(func() {
			if failure != "" {
				walk.App().Exit(1)
			} else {
				walk.App().Exit(0)
			}
		})
	}()
	if scenario == "update-offer" {
		syncUI(func() {
			tp := window.tunnelsPage
			offer := tp.r013Upgrade
			if offer == nil || offer.row.Visible() {
				failure = "Install offer missing or visible before discovery"
				return
			}
			checks = append(checks, "Install button is hidden before an update is discovered")
			tp.showR013Upgrade(&r013.Release{Version: version.Number, Build: r013.CurrentBuild})
			if offer.row.Visible() || offer.release != nil {
				failure = "Installed build offered again"
				return
			}
			checks = append(checks, "Currently installed build is not offered again")
			tp.listView.selectTunnel("Germany")
			candidate := &r013.Release{Version: version.Number, Build: r013.CurrentBuild + 1}
			tp.showR013Upgrade(candidate)
			if !offer.row.Visible() || !offer.button.Enabled() || offer.button.Text() != "Установить обновление" {
				failure = "Newer build does not expose the install button"
				return
			}
			checks = append(checks, "Newer build exposes the enabled Install update button")
			candidate.Build++
			if offer.release.Build != r013.CurrentBuild+1 {
				failure = "Offered metadata was not copied"
				return
			}
			checks = append(checks, "Offer retains an immutable release copy")
			if offer.installing || tp.listView.CurrentTunnel() == nil || tp.listView.CurrentTunnel().Name != "Germany" {
				failure = "Discovery installed software or changed the selected profile"
				return
			}
			checks = append(checks, "Discovery preserves selection and never starts installation")
			tp.showR013Upgrade(nil)
			if offer.row.Visible() || offer.release != nil {
				failure = "Cleared offer remains actionable"
				return
			}
			checks = append(checks, "Clearing discovery removes the actionable offer")
		})
		return
	}
	deadline := time.Now().Add(15 * time.Second)
	ready := false
	for !ready && time.Now().Before(deadline) {
		syncUI(func() { ready = window.currentCard.current.active })
		if !ready {
			time.Sleep(30 * time.Millisecond)
		}
	}
	if !ready {
		failure = "Current fixture did not become active"
		return
	}
	if scenario == "power" {
		check := func(ok bool, message string) bool {
			if !ok {
				failure = message
				return false
			}
			checks = append(checks, message)
			return true
		}
		capture := func(name string) {
			syncUI(func() {
				if name == "connected" {
					window.SetBounds(walk.Rectangle{X: 8, Y: 8, Width: 980, Height: 700})
				}
				window.Show()
				win.ShowWindow(window.Handle(), win.SW_SHOWNORMAL)
				win.SetForegroundWindow(window.Handle())
				win.RedrawWindow(window.Handle(), nil, 0, win.RDW_INVALIDATE|win.RDW_UPDATENOW|win.RDW_ALLCHILDREN)
			})
			// Let the native layout/paint messages run before capturing the desktop.
			time.Sleep(250 * time.Millisecond)
			syncUI(func() {
				var rect, power win.RECT
				if !win.GetWindowRect(window.Handle(), &rect) || !win.GetWindowRect(window.currentCard.power.Handle(), &power) {
					failure = "Native window bounds unavailable"
					return
				}
				if power.Left < rect.Left || power.Right > rect.Right || power.Top < rect.Top || power.Bottom > rect.Bottom || power.Bottom-power.Top < 80 {
					failure = "Power control clipped outside native window"
					return
				}
				bitmap, err := walk.NewBitmapForDPI(walk.Size{Width: int(rect.Right - rect.Left), Height: int(rect.Bottom - rect.Top)}, 96)
				if err != nil {
					failure = "Native bitmap failed"
					return
				}
				defer bitmap.Dispose()
				canvas, err := walk.NewCanvasFromImage(bitmap)
				if err != nil {
					failure = "Native capture canvas failed"
					return
				}
				dc := win.GetDC(0)
				ok := win.BitBlt(canvas.HDC(), 0, 0, rect.Right-rect.Left, rect.Bottom-rect.Top, dc, rect.Left, rect.Top, win.SRCCOPY)
				win.ReleaseDC(0, dc)
				canvas.Dispose()
				if !ok {
					failure = "Native desktop capture failed"
					return
				}
				image, err := bitmap.ToImage()
				if err != nil {
					failure = "Native image conversion failed"
					return
				}
				navy, palePixels := 0, 0
				for y := 0; y < image.Bounds().Dy(); y++ {
					for x := 0; x < image.Bounds().Dx(); x++ {
						pixel := image.RGBAAt(x, y)
						if pixel.R == 12 && pixel.G == 25 && pixel.B == 41 {
							navy++
						}
						if pixel.R == 220 && pixel.G == 234 && pixel.B == 244 {
							palePixels++
						}
					}
				}
				if navy < image.Bounds().Dx()*image.Bounds().Dy()/20 || palePixels < 50 {
					failure = "Native desktop did not render the actual application content"
					return
				}
				file, err := os.Create(filepath.Join(filepath.Dir(destination), "r013-power-"+name+".png"))
				if err != nil {
					failure = "Native capture file failed"
					return
				}
				defer file.Close()
				if png.Encode(file, image) != nil {
					failure = "Native PNG encoding failed"
				}
			})
		}
		wait := func(active bool, name string) bool {
			until := time.Now().Add(10 * time.Second)
			for time.Now().Before(until) {
				ok := false
				syncUI(func() {
					c := window.currentCard
					ok = !c.powerBusy && !c.powerRefreshing && c.current.controlKnown && c.current.active == active && (!active || c.current.controlName == name)
				})
				if ok {
					return true
				}
				time.Sleep(20 * time.Millisecond)
			}
			failure = "Power action did not settle"
			return false
		}
		syncUI(func() {
			c := window.currentCard
			window.tunnelsPage.listView.selectTunnel("Germany")
			if !check(c.power.Visible() && c.power.Enabled() && c.power.Text() == "ВЫКЛ" && c.current.controlName == "Finland", "Native OFF button follows active Finland while Germany is selected") {
				return
			}
			c.power.SetFocus()
			if !check(win.GetFocus() == c.power.Handle(), "Power control receives native keyboard focus") {
				return
			}
		})
		if failure != "" {
			return
		}
		capture("connected")
		if failure != "" {
			return
		}
		syncUI(func() {
			c := window.currentCard
			c.power.SendMessage(win.BM_CLICK, 0, 0)
			c.power.SendMessage(win.BM_CLICK, 0, 0)
		})
		if failure != "" || !wait(false, "") {
			return
		}
		syncUI(func() {
			c := window.currentCard
			a, b, _, last := R013PreviewPowerAudit()
			if !check(a == 0 && b == 1 && last == "Finland" && c.power.Enabled() && c.power.Text() == "ВКЛ", "Double click sends exactly one STOP for actual active profile") {
				return
			}
		})
		if failure != "" {
			return
		}
		capture("disconnected")
		if failure != "" {
			return
		}
		syncUI(func() {
			c := window.currentCard
			c.power.SendMessage(win.BM_CLICK, 0, 0)
		})
		if failure != "" || !wait(false, "") {
			return
		}
		syncUI(func() {
			c := window.currentCard
			a, b, last, _ := R013PreviewPowerAudit()
			if !check(a == 1 && b == 1 && last == "Germany" && c.powerError.Visible() && c.power.Enabled(), "Failed START restores an actionable button and reports failure without claiming connection") {
				return
			}
			c.power.SendMessage(win.BM_CLICK, 0, 0)
		})
		if failure != "" || !wait(true, "Germany") {
			return
		}
		syncUI(func() {
			c := window.currentCard
			a, b, last, _ := R013PreviewPowerAudit()
			if !check(a == 2 && b == 1 && last == "Germany" && c.power.Text() == "ВЫКЛ" && !c.powerError.Visible(), "Retry START activates exactly selected Germany and clears prior error") {
				return
			}
			window.tunnelsPage.listView.selectTunnel("Netherlands")
			c.power.SendMessage(win.BM_CLICK, 0, 0)
		})
		if failure != "" || !wait(false, "") {
			return
		}
		syncUI(func() {
			c := window.currentCard
			_, b, _, last := R013PreviewPowerAudit()
			if !check(b == 2 && last == "Germany", "OFF after a selection change still stops Germany rather than starting Netherlands") {
				return
			}
			window.tunnelsPage.listView.selectTunnel(r013.AutoName)
			c.power.SendMessage(win.BM_CLICK, 0, 0)
		})
		if failure != "" || !wait(true, r013.AutoName) {
			return
		}
		syncUI(func() {
			c := window.currentCard
			a, _, last, _ := R013PreviewPowerAudit()
			if !check(a == 3 && last == r013.AutoName && c.power.Text() == "ВЫКЛ", "Power control starts Auto through the same manager path") {
				return
			}
		})
		if failure != "" {
			return
		}
		capture("auto")
		if failure != "" {
			return
		}
		syncUI(func() {
			c := window.currentCard
			c.power.SendMessage(win.BM_CLICK, 0, 0)
		})
		if failure != "" || !wait(false, "") {
			return
		}
		syncUI(func() {
			c := window.currentCard
			_, b, _, last := R013PreviewPowerAudit()
			if !check(b == 3 && last == r013.AutoName, "Power control stops the actual Auto session") {
				return
			}
			for _, state := range []manager.TunnelState{manager.TunnelStarting, manager.TunnelStopping, manager.TunnelUnknown} {
				c.apply(r013CurrentSnapshot{controlKnown: state != manager.TunnelUnknown, controlState: state}, c.revision.Load())
				if c.power.Enabled() {
					failure = "Transient or unknown manager state is actionable"
					return
				}
			}
			if !check(true, "Starting, stopping and unknown manager states disable power actions") {
				return
			}
			window.tunnelsPage.listView.SetCurrentIndex(-1)
			c.apply(r013CurrentSnapshot{controlKnown: true, controlState: manager.TunnelStopped}, c.revision.Load())
			a, finalStops, _, _ := R013PreviewPowerAudit()
			check(!c.power.Enabled() && a == 3 && finalStops == 3, "Empty selection cannot issue a command and state-only checks never change VPN")
			window.SetSize(walk.Size{Width: 820, Height: 560})
			window.tunnelsPage.listView.selectTunnel("Germany")
			c.apply(r013CurrentSnapshot{controlKnown: true, controlState: manager.TunnelStopped, detail: "VPN не подключён"}, c.revision.Load())
		})
		if failure != "" {
			return
		}
		capture("minimum-window")
		return
	}
	syncUI(func() {
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
		syncUI(func() { complete = window.currentCard.pingCancel == nil })
		if !complete {
			time.Sleep(30 * time.Millisecond)
		}
	}
	syncUI(func() {
		text := window.currentCard.result.Text()
		if !complete || !strings.Contains(text, "мс") {
			failure = fmt.Sprintf("Actual loopback current ping did not complete: %s", text)
			return
		}
		checks = append(checks, "Current button performs real OS loopback ICMP and displays milliseconds")
		echoVerified = true
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
