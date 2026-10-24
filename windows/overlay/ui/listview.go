/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

package ui

import (
	"sort"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"

	"github.com/lxn/walk"
)

// ListModel is a struct to store the currently known tunnels to the GUI, suitable as a model for a walk.TableView.
type ListModel struct {
	walk.TableModelBase
	walk.SorterBase

	tunnels           []manager.Tunnel
	lastObservedState map[manager.Tunnel]manager.TunnelState
	pings             map[string]string
}

func (t *ListModel) RowCount() int {
	return len(t.tunnels)
}

func (t *ListModel) Value(row, col int) any {
	if row < 0 || row >= len(t.tunnels) {
		return ""
	}
	if col == 1 {
		if result, ok := t.pings[t.tunnels[row].Name]; ok {
			return result
		}
		return "—"
	}
	if t.tunnels[row].Name == "R013-Auto" {
		return "Авто"
	}
	return t.tunnels[row].Name
}

func (t *ListModel) Sort(col int, order walk.SortOrder) error {
	sort.SliceStable(t.tunnels, func(i, j int) bool {
		return r013.ProfileNameLess(t.tunnels[i].Name, t.tunnels[j].Name)
	})

	return t.SorterBase.Sort(col, order)
}

type ListView struct {
	*walk.TableView

	model *ListModel

	tunnelChangedCB        *manager.TunnelChangeCallback
	tunnelsChangedCB       *manager.TunnelsChangeCallback
	tunnelsUpdateSuspended int32
}

func NewListView(parent walk.Container) (*ListView, error) {
	var disposables walk.Disposables
	defer disposables.Treat()

	tv, err := walk.NewTableView(parent)
	if err != nil {
		return nil, err
	}
	disposables.Add(tv)

	// SysListView32 already uses LVS_EX_DOUBLEBUFFER. Compositing its wrapper
	// can paint the wrapper background over the child list on some systems.
	tv.SetDoubleBuffering(false)

	model := new(ListModel)
	model.lastObservedState = make(map[manager.Tunnel]manager.TunnelState)
	model.pings = make(map[string]string)
	tv.SetModel(model)
	tv.SetLastColumnStretched(true)
	tv.SetHeaderHidden(false)
	tv.SetIgnoreNowhere(true)
	tv.SetScrollbarOrientation(walk.Vertical)
	nameColumn := walk.NewTableViewColumn()
	nameColumn.SetTitle("Профили")
	nameColumn.SetWidth(250)
	tv.Columns().Add(nameColumn)
	pingColumn := walk.NewTableViewColumn()
	pingColumn.SetTitle("Пинг")
	pingColumn.SetWidth(100)
	tv.Columns().Add(pingColumn)

	tunnelsView := &ListView{
		TableView: tv,
		model:     model,
	}
	tv.SetCellStyler(tunnelsView)
	tv.SetPalette(night, pale, selectedNight, pale)

	disposables.Spare()

	tunnelsView.tunnelChangedCB = manager.IPCClientRegisterTunnelChange(tunnelsView.onTunnelChange)
	tunnelsView.tunnelsChangedCB = manager.IPCClientRegisterTunnelsChange(tunnelsView.onTunnelsChange)

	return tunnelsView, nil
}

func (tv *ListView) Dispose() {
	if tv.tunnelChangedCB != nil {
		tv.tunnelChangedCB.Unregister()
		tv.tunnelChangedCB = nil
	}
	if tv.tunnelsChangedCB != nil {
		tv.tunnelsChangedCB.Unregister()
		tv.tunnelsChangedCB = nil
	}
	tv.TableView.Dispose()
}

func (tv *ListView) CurrentTunnel() *manager.Tunnel {
	idx := tv.CurrentIndex()
	if idx == -1 {
		return nil
	}

	return &tv.model.tunnels[idx]
}

func (tv *ListView) StyleCell(style *walk.CellStyle) {
	style.BackgroundColor = night
	style.TextColor = pale
	row := style.Row()
	if row < 0 || row >= len(tv.model.tunnels) {
		return
	}
	tunnel := &tv.model.tunnels[row]
	if row == tv.CurrentIndex() {
		style.BackgroundColor = selectedNight
	}
	if style.Col() == 1 {
		style.TextColor = muted
		return
	}
	if style.Col() != 0 {
		return
	}

	var state manager.TunnelState
	var ok bool
	state, ok = tv.model.lastObservedState[tv.model.tunnels[row]]
	if !ok {
		var err error
		state, err = tunnel.State()
		if err != nil {
			return
		}
		tv.model.lastObservedState[tv.model.tunnels[row]] = state
	}

	icon, err := iconForState(state, 14)
	if err != nil {
		return
	}
	style.Image = icon
}

func (tv *ListView) onTunnelChange(tunnel *manager.Tunnel, state, globalState manager.TunnelState, err error) {
	tv.Synchronize(func() {
		idx := -1
		for i := range tv.model.tunnels {
			if tv.model.tunnels[i].Name == tunnel.Name {
				idx = i
				break
			}
		}

		if idx != -1 {
			tv.model.lastObservedState[tv.model.tunnels[idx]] = state
			tv.model.PublishRowChanged(idx)
			return
		}
	})
}

func (tv *ListView) onTunnelsChange() {
	if atomic.LoadInt32(&tv.tunnelsUpdateSuspended) == 0 {
		tv.Load(true)
	}
}

func (tv *ListView) SetSuspendTunnelsUpdate(suspend bool) {
	if suspend {
		atomic.AddInt32(&tv.tunnelsUpdateSuspended, 1)
	} else {
		atomic.AddInt32(&tv.tunnelsUpdateSuspended, -1)
	}
	tv.Load(true)
}

func (tv *ListView) Load(asyncUI bool) {
	tunnels, err := manager.IPCClientTunnels()
	if err != nil {
		return
	}
	doUI := func() {
		newTunnels := make(map[manager.Tunnel]bool, len(tunnels))
		oldTunnels := make(map[manager.Tunnel]bool, len(tv.model.tunnels))
		for _, tunnel := range tunnels {
			newTunnels[tunnel] = true
		}
		for i := len(tv.model.tunnels); i > 0; {
			i--
			tunnel := tv.model.tunnels[i]
			oldTunnels[tunnel] = true
			if !newTunnels[tunnel] {
				tv.model.tunnels = append(tv.model.tunnels[:i], tv.model.tunnels[i+1:]...)
				tv.model.PublishRowsRemoved(i, i) // TODO: Do we have to call that everytime or can we pass a range?
				delete(tv.model.lastObservedState, tunnel)
			}
		}
		didAdd := false
		firstTunnelName := ""
		for tunnel := range newTunnels {
			if !oldTunnels[tunnel] {
				if len(firstTunnelName) == 0 || !conf.TunnelNameIsLess(firstTunnelName, tunnel.Name) {
					firstTunnelName = tunnel.Name
				}
				tv.model.tunnels = append(tv.model.tunnels, tunnel)
				didAdd = true
			}
		}
		if didAdd {
			tv.model.PublishRowsReset()
			tv.model.Sort(tv.model.SortedColumn(), tv.model.SortOrder())
			if len(tv.SelectedIndexes()) == 0 {
				tv.selectTunnel(firstTunnelName)
			}
		}
	}
	if asyncUI {
		tv.Synchronize(doUI)
	} else {
		doUI()
	}
}

func (tv *ListView) selectTunnel(tunnelName string) {
	for i, tunnel := range tv.model.tunnels {
		if tunnel.Name == tunnelName {
			tv.SetCurrentIndex(i)
			break
		}
	}
}

func (tv *ListView) SelectFirstActiveTunnel() {
	tunnels := make([]manager.Tunnel, len(tv.model.tunnels))
	copy(tunnels, tv.model.tunnels)
	go func() {
		for _, tunnel := range tunnels {
			state, err := tunnel.State()
			if err != nil {
				continue
			}
			if state == manager.TunnelStarting || state == manager.TunnelStarted {
				tv.Synchronize(func() {
					tv.selectTunnel(tunnel.Name)
				})
				return
			}
		}
	}()
}
