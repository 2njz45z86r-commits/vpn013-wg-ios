// SPDX-License-Identifier: MIT
package ui

import (
	"errors"
	"sort"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"github.com/lxn/walk"
)

var serviceGetTargets = manager.IPCClientGetServiceTargets
var serviceGetPolicies = manager.IPCClientGetServicePolicies
var serviceUpdatePolicies = manager.IPCClientUpdateServicePolicies

type serviceDialogInspection struct {
	dialog       *walk.Dialog
	services     *serviceRows
	targets      *serviceTargets
	only, bypass *walk.CheckBox
	group        *walk.ComboBox
	search       *walk.LineEdit
	all, clear   *walk.PushButton
}

// Only the separately tagged preview can set this hook; normal application
// operation leaves it nil and all RPCs use the real protected manager.
var serviceDialogPreviewHook func(serviceDialogInspection)

type serviceRows struct {
	walk.TableModelBase
	catalog                *r013routing.ServiceCatalog
	rows                   []r013routing.CatalogService
	selection              *r013routing.ServiceSelection
	dirtyOnly, dirtyBypass bool
}

func (m *serviceRows) RowCount() int { return len(m.rows) }
func (m *serviceRows) Value(row, col int) interface{} {
	s := m.rows[row]
	if col == 0 {
		return s.Icon.Text + "  " + s.Name
	}
	if !m.catalog.SupportsWireGuard(s.ID) {
		return "Недоступно для WireGuard"
	}
	return ""
}
func (m *serviceRows) current() *[]string {
	if m.selection.EffectiveMode() == r013routing.ServicesBypass {
		return &m.selection.Bypass
	}
	return &m.selection.Only
}
func (m *serviceRows) Checked(i int) bool {
	for _, id := range *m.current() {
		if id == m.rows[i].ID {
			return true
		}
	}
	return false
}
func (m *serviceRows) SetChecked(i int, on bool) error {
	if m.selection.EffectiveMode() == r013routing.ServicesUnchanged {
		return errors.New("Сначала выберите режим.")
	}
	id := m.rows[i].ID
	if on && !m.catalog.SupportsWireGuard(id) {
		return errors.New("Этот сервис пока недоступен для WireGuard.")
	}
	ids := m.current()
	next := make([]string, 0, len(*ids)+1)
	for _, v := range *ids {
		if v != id {
			next = append(next, v)
		}
	}
	if on {
		next = append(next, id)
	}
	sort.Strings(next)
	*ids = next
	if m.selection.EffectiveMode() == r013routing.ServicesOnly {
		m.dirtyOnly = true
	} else {
		m.dirtyBypass = true
	}
	return nil
}

type serviceTargets struct {
	walk.TableModelBase
	names       []string
	selected    map[string]bool
	unavailable map[string]bool
}

func (m *serviceTargets) RowCount() int { return len(m.names) }
func (m *serviceTargets) Value(row, col int) interface{} {
	if strings.EqualFold(m.names[row], r013.AutoName) {
		if m.unavailable[m.names[row]] {
			return "Авто · недоступно"
		}
		return "Авто"
	}
	return m.names[row]
}
func (m *serviceTargets) Checked(i int) bool             { return m.selected[m.names[i]] }
func (m *serviceTargets) SetChecked(i int, v bool) error { m.selected[m.names[i]] = v; return nil }
func makeServiceTable(parent walk.Container, model interface{}, columns ...string) (*walk.TableView, error) {
	table, err := walk.NewTableView(parent)
	if err != nil {
		return nil, err
	}
	table.SetDoubleBuffering(false)
	table.SetCheckBoxes(true)
	table.SetLastColumnStretched(true)
	for _, title := range columns {
		column := walk.NewTableViewColumn()
		column.SetTitle(title)
		column.SetWidth(250)
		if err = table.Columns().Add(column); err != nil {
			return nil, err
		}
	}
	if err = table.SetModel(model); err != nil {
		return nil, err
	}
	return table, nil
}
func (tp *TunnelsPage) onServiceRouting() {
	if r013Preview && serviceDialogPreviewHook == nil {
		showErrorCustom(tp.Form(), "Сервисы", "В предпросмотре настройки не сохраняются.")
		return
	}
	cat, err := r013routing.OwnerCatalog()
	if err != nil {
		showErrorCustom(tp.Form(), "Сервисы", err.Error())
		return
	}
	tunnels, err := serviceGetTargets()
	if err != nil {
		showErrorCustom(tp.Form(), "Сервисы", err.Error())
		return
	}
	target := &serviceTargets{selected: map[string]bool{}, unavailable: map[string]bool{}}
	digests := make(map[string]string, len(tunnels))
	for _, t := range tunnels {
		target.names = append(target.names, t.Name)
		digests[t.Name] = t.SourceDigest
		if t.SourceDigest == "" {
			target.unavailable[t.Name] = true
		}
	}
	sort.Strings(target.names)
	dlg, err := walk.NewDialog(tp.Form())
	if err != nil {
		return
	}
	defer dlg.Dispose()
	dlg.SetTitle("Сервисы и маршруты IPv4")
	dlg.SetLayout(walk.NewVBoxLayout())
	dlg.SetMinMaxSize(walk.Size{Width: 700, Height: 650}, walk.Size{})
	dlg.SetSize(walk.Size{Width: 760, Height: 780})
	note, _ := walk.NewTextLabel(dlg)
	note.SetText("Когда оба переключателя выключены, сохраняются прежние маршруты. Выберите сервисы и серверы; для применения отключите выбранные серверы. IPv6 не меняется.")
	modes, _ := walk.NewComposite(dlg)
	modes.SetLayout(walk.NewHBoxLayout())
	only, _ := walk.NewCheckBox(modes)
	only.SetText("Только выбранные через VPN")
	bypass, _ := walk.NewCheckBox(modes)
	bypass.SetText("Выбранные в обход VPN")
	search, _ := walk.NewLineEdit(dlg)
	search.SetToolTipText("Поиск сервиса")
	search.SetCueBanner("Поиск сервиса")
	groups := cat.DisplayGroups("")
	titles := []string{"Все группы"}
	for _, g := range groups {
		titles = append(titles, g.Title)
	}
	group, _ := walk.NewComboBox(dlg)
	group.SetModel(titles)
	group.SetCurrentIndex(0)
	selection := r013routing.ServiceSelection{}
	services := &serviceRows{catalog: cat, selection: &selection}
	_, err = makeServiceTable(dlg, services, "Сервис", "Доступность")
	if err != nil {
		showErrorCustom(tp.Form(), "Сервисы", err.Error())
		return
	}
	refresh := func() {
		services.rows = nil
		for _, g := range cat.DisplayGroups(search.Text()) {
			if group.CurrentIndex() > 0 && g.Title != titles[group.CurrentIndex()] {
				continue
			}
			services.rows = append(services.rows, g.Services...)
		}
		services.PublishRowsReset()
	}
	search.TextChanged().Attach(refresh)
	group.CurrentIndexChanged().Attach(refresh)
	only.CheckedChanged().Attach(func() {
		if only.Checked() {
			bypass.SetChecked(false)
		}
		selection.SetOnly(only.Checked())
		services.PublishRowsReset()
	})
	bypass.CheckedChanged().Attach(func() {
		if bypass.Checked() {
			only.SetChecked(false)
		}
		selection.SetBypass(bypass.Checked())
		services.PublishRowsReset()
	})
	refresh()
	targetLabel, _ := walk.NewTextLabel(dlg)
	targetLabel.SetText("Серверы: ни один не выбран автоматически. Для Авто проверяются все его серверы.")
	_, err = makeServiceTable(dlg, target, "Сервер")
	if err != nil {
		showErrorCustom(tp.Form(), "Сервисы", err.Error())
		return
	}
	controls, _ := walk.NewComposite(dlg)
	controls.SetLayout(walk.NewHBoxLayout())
	all, _ := walk.NewPushButton(controls)
	all.SetText("Выбрать все серверы")
	all.Clicked().Attach(func() {
		for _, n := range target.names {
			target.selected[n] = true
		}
		target.PublishRowsReset()
	})
	clear, _ := walk.NewPushButton(controls)
	clear.SetText("Очистить серверы")
	clear.Clicked().Attach(func() { target.selected = map[string]bool{}; target.PublishRowsReset() })
	load, _ := walk.NewPushButton(controls)
	load.SetText("Загрузить выбор сервера")
	load.Clicked().Attach(func() {
		names := []string{}
		for _, n := range target.names {
			if target.selected[n] {
				names = append(names, n)
			}
		}
		if len(names) != 1 {
			showErrorCustom(dlg, "Сервисы", "Отметьте один сервер для загрузки его выбора.")
			return
		}
		doc, e := serviceGetPolicies()
		if e != nil {
			showErrorCustom(dlg, "Сервисы", e.Error())
			return
		}
		selection = r013routing.ServiceSelection{}
		services.dirtyOnly, services.dirtyBypass = false, false
		for _, p := range doc.Profiles {
			if strings.EqualFold(p.Name, names[0]) {
				selection = p.Selection
				break
			}
		}
		loadedMode := selection.EffectiveMode()
		only.SetChecked(loadedMode == r013routing.ServicesOnly)
		bypass.SetChecked(loadedMode == r013routing.ServicesBypass)
		selection.Mode = loadedMode
		services.PublishRowsReset()
	})
	actions, _ := walk.NewComposite(dlg)
	actions.SetLayout(walk.NewHBoxLayout())
	walk.NewHSpacer(actions)
	apply, _ := walk.NewPushButton(actions)
	apply.SetText("Применить")
	cancel, _ := walk.NewPushButton(actions)
	cancel.SetText("Отмена")
	cancel.Clicked().Attach(dlg.Cancel)
	dlg.SetCancelButton(cancel)
	apply.Clicked().Attach(func() {
		for _, name := range target.names {
			if target.selected[name] && target.unavailable[name] {
				showErrorCustom(dlg, "Не применено", "Авто недоступно для проверки. Снимите его отметку или восстановите состав Авто и откройте настройки снова.")
				return
			}
		}
		doc, e := serviceGetPolicies()
		if e != nil {
			showErrorCustom(dlg, "Сервисы", e.Error())
			return
		}
		existing := map[string]r013routing.ServiceSelection{}
		for _, p := range doc.Profiles {
			existing[strings.ToLower(p.Name)] = p.Selection
		}
		changes := []r013routing.ProfilePolicy{}
		for _, name := range target.names {
			if !target.selected[name] {
				continue
			}
			next := existing[strings.ToLower(name)]
			next.Mode = selection.EffectiveMode()
			if next.Mode == r013routing.ServicesOnly || services.dirtyOnly {
				next.Only = append([]string(nil), selection.Only...)
			}
			if next.Mode == r013routing.ServicesBypass || services.dirtyBypass {
				next.Bypass = append([]string(nil), selection.Bypass...)
			}
			changes = append(changes, r013routing.ProfilePolicy{Name: name, SourceDigest: digests[name], Selection: next})
		}
		if len(changes) == 0 {
			showErrorCustom(dlg, "Сервисы", "Отметьте хотя бы один сервер.")
			return
		}
		if e = serviceUpdatePolicies(changes); e != nil {
			showErrorCustom(dlg, "Не применено", e.Error())
			return
		}
		walk.MsgBox(dlg, "Сервисы", "Настройки сохранены. Они применятся при следующем подключении выбранных серверов.", walk.MsgBoxOK|walk.MsgBoxIconInformation)
		dlg.Accept()
	})
	if serviceDialogPreviewHook != nil {
		serviceDialogPreviewHook(serviceDialogInspection{dlg, services, target, only, bypass, group, search, all, clear})
	}
	dlg.Run()
}
