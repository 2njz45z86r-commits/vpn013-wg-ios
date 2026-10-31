// SPDX-License-Identifier: MIT
package ui

import (
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"testing"
)

func TestServiceChooserStartsEmptyRetainsModeSelections(t *testing.T) {
	cat, err := r013routing.OwnerCatalog()
	if err != nil {
		t.Fatal(err)
	}
	rows := cat.DisplayServices()
	selection := r013routing.ServiceSelection{}
	m := &serviceRows{catalog: cat, rows: rows, selection: &selection}
	targets := &serviceTargets{names: []string{"A", "B"}, selected: map[string]bool{}}
	if targets.Checked(0) || targets.Checked(1) || len(selection.Only)+len(selection.Bypass) != 0 {
		t.Fatal("initially selected")
	}
	idx := -1
	for i, s := range rows {
		if cat.SupportsWireGuard(s.ID) {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatal("no supported fixture")
	}
	if m.SetChecked(idx, true) == nil {
		t.Fatal("off mode accepted choice")
	}
	selection.SetOnly(true)
	if err = m.SetChecked(idx, true); err != nil || !m.Checked(idx) {
		t.Fatal("only choice not selected")
	}
	selection.SetBypass(true)
	if m.Checked(idx) {
		t.Fatal("inactive selection appeared active")
	}
	if err = m.SetChecked(idx, true); err != nil {
		t.Fatal(err)
	}
	selection.SetBypass(false)
	if len(selection.Only) != 1 || len(selection.Bypass) != 1 {
		t.Fatal("mode switch lost choices")
	}
	if err = targets.SetChecked(1, true); err != nil || targets.Checked(0) || !targets.Checked(1) {
		t.Fatal("server selection leaked")
	}
}
func TestServiceChooserRejectsDomainOnlyRows(t *testing.T) {
	cat, err := r013routing.OwnerCatalog()
	if err != nil {
		t.Fatal(err)
	}
	rows := cat.DisplayServices()
	m := &serviceRows{catalog: cat, rows: rows, selection: &r013routing.ServiceSelection{Mode: r013routing.ServicesOnly}}
	found := false
	for i, s := range rows {
		if !cat.SupportsWireGuard(s.ID) {
			found = true
			if m.SetChecked(i, true) == nil {
				t.Fatal("unsupported service selected")
			}
		}
	}
	if !found {
		t.Fatal("expected unsupported fixture")
	}
}
