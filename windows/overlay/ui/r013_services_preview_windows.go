//go:build r013preview

// SPDX-License-Identifier: MIT
package ui

import (
	"errors"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"github.com/lxn/walk"
	"github.com/lxn/win"
)

// Native controls are driven with synthetic targets and never call a service.
func verifyR013ServicePreview(window *ManageTunnelsWindow, destination string, syncUI func(func()), checks *[]string) (failure string) {
	oldTargets, oldPolicies, oldUpdate, oldHook := serviceGetTargets, serviceGetPolicies, serviceUpdatePolicies, serviceDialogPreviewHook
	defer func() {
		serviceGetTargets, serviceGetPolicies, serviceUpdatePolicies, serviceDialogPreviewHook = oldTargets, oldPolicies, oldUpdate, oldHook
	}()
	writes := 0
	serviceGetTargets = func() ([]manager.ServiceTarget, error) {
		return []manager.ServiceTarget{{Name: "Germany", SourceDigest: strings.Repeat("a", 64)}, {Name: "R013-Auto", SourceDigest: strings.Repeat("b", 64)}}, nil
	}
	serviceGetPolicies = func() (r013routing.ServicePolicies, error) { return r013routing.ServicePolicies{Version: 1}, nil }
	serviceUpdatePolicies = func([]r013routing.ProfilePolicy) error { writes++; return errors.New("preview never writes") }
	serviceDialogPreviewHook = func(s serviceDialogInspection) {
		go func() {
			s.dialog.Synchronize(func() {
				defer s.dialog.Cancel()
				check := func(ok bool, text string) bool {
					if !ok {
						failure = text
						return false
					}
					*checks = append(*checks, text)
					return true
				}
				if !check(!s.only.Checked() && !s.bypass.Checked() && len(s.services.selection.Only) == 0 && len(s.services.selection.Bypass) == 0 && !s.targets.Checked(0) && !s.targets.Checked(1), "Modes and servers initially unselected") {
					return
				}
				if !check(len(s.group.Model().([]string)) == 24 && len(s.services.rows) == 412, "All 23 groups and 412 services displayed") {
					return
				}
				s.search.SetText("Telegram")
				if !check(len(s.services.rows) > 0 && strings.Contains(strings.ToLower(s.services.rows[0].Name), "telegram"), "Search filters real service names") {
					return
				}
				s.search.SetText("")
				s.only.SetChecked(true)
				index := -1
				for i, v := range s.services.rows {
					if s.services.catalog.SupportsWireGuard(v.ID) {
						index = i
						break
					}
				}
				if !check(index >= 0 && s.services.SetChecked(index, true) == nil && s.services.Checked(index), "ONLY mode accepts explicit service") {
					return
				}
				s.bypass.SetChecked(true)
				if !check(!s.only.Checked() && s.bypass.Checked() && !s.services.Checked(index) && len(s.services.selection.Only) == 1, "BYPASS excludes inactive selection") {
					return
				}
				s.all.SendMessage(win.BM_CLICK, 0, 0)
				if !check(s.targets.Checked(0) && s.targets.Checked(1), "Select all applies only to servers") {
					return
				}
				s.clear.SendMessage(win.BM_CLICK, 0, 0)
				if !check(!s.targets.Checked(0) && !s.targets.Checked(1), "Clear removes server selections") {
					return
				}
				unsupported := -1
				for i, v := range s.services.rows {
					if !s.services.catalog.SupportsWireGuard(v.ID) {
						unsupported = i
						break
					}
				}
				if !check(unsupported >= 0 && s.services.SetChecked(unsupported, true) != nil && writes == 0, "Unsupported service is unavailable and preview made no writes") {
					return
				}
				bitmap, err := walk.NewBitmapFromWindow(s.dialog)
				if err != nil {
					failure = "Service dialog screenshot failed"
					return
				}
				defer bitmap.Dispose()
				picture, err := bitmap.ToImage()
				if err != nil {
					failure = "Service image conversion failed"
					return
				}
				r013OpaquePreviewCapture(picture)
				file, err := os.Create(filepath.Join(filepath.Dir(destination), "r013-services.png"))
				if err != nil {
					failure = "Service screenshot file failed"
					return
				}
				defer file.Close()
				if png.Encode(file, picture) != nil {
					failure = "Service screenshot encoding failed"
				}
			})
		}()
	}
	syncUI(func() { window.tunnelsPage.onServiceRouting() })
	return
}
