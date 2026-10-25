// SPDX-License-Identifier: MIT
package ui

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/version"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/lxn/walk"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

var night = walk.RGB(12, 25, 41)
var pale = walk.RGB(220, 234, 244)
var muted = walk.RGB(157, 178, 197)
var warm = walk.RGB(232, 182, 108)
var selectedNight = walk.RGB(25, 53, 74)
var r013Preview bool
var nightBrush *walk.SolidColorBrush
var nativeChromeBrush *walk.SystemColorBrush

func externalLink(owner walk.Form, url string) {
	win.ShellExecute(owner.Handle(), nil, windows.StringToUTF16Ptr(url), nil, nil, win.SW_SHOWNORMAL)
}
func themeWindow(window walk.Window) {
	// Native navigation controls do not expose a custom foreground. Keep their
	// system surface so captions and keyboard focus remain readable.
	switch window.(type) {
	case *walk.TableView:
		// The native child list paints its own surface. Painting the composite
		// wrapper as well can cover its rows with WS_EX_COMPOSITED enabled.
	case *walk.ToolBar, *walk.TabWidget:
		if nativeChromeBrush == nil {
			nativeChromeBrush, _ = walk.NewSystemColorBrush(walk.SysColorBtnFace)
		}
		window.SetBackground(nativeChromeBrush)
	case *walk.PushButton:
		// Keep the OS's button text/background contrast and focus rules.
	default:
		if nightBrush == nil {
			nightBrush, _ = walk.NewSolidColorBrush(night)
		}
		if window.Background() != nightBrush {
			window.SetBackground(nightBrush)
		}
	}
	if table, ok := window.(*walk.TableView); ok {
		table.SetPalette(night, pale, selectedNight, pale)
	}
	if text, ok := window.(interface{ SetTextColor(walk.Color) }); ok {
		text.SetTextColor(pale)
	}
	if container, ok := window.(walk.Container); ok {
		for i := 0; i < container.Children().Len(); i++ {
			themeWindow(container.Children().At(i))
		}
	}
}
func addR013Header(mtw *ManageTunnelsWindow) {
	header, _ := walk.NewComposite(mtw)
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{16, 10, 16, 4})
	header.SetLayout(layout)
	title, _ := walk.NewLabel(header)
	title.SetText("VPN013 WG")
	font, _ := walk.NewFont("Segoe UI", 17, walk.FontBold)
	title.SetFont(font)
	title.SetTextColor(pale)
	walk.NewHSpacer(header)
	ping, _ := walk.NewPushButton(header)
	ping.SetText("Проверить пинг")
	ping.SetMinMaxSize(walk.Size{138, 34}, walk.Size{138, 34})
	ping.Clicked().Attach(func() { mtw.tunnelsPage.onPingAll(ping) })
	updates, _ := walk.NewPushButton(header)
	updates.SetText("Обновить")
	updates.SetMinMaxSize(walk.Size{110, 34}, walk.Size{110, 34})
	updates.Clicked().Attach(func() { mtw.tunnelsPage.onR013Updates() })
	note, _ := walk.NewLabel(mtw)
	note.SetText("Пинг измеряется по текущему маршруту. Проверка не переключает VPN.")
	note.SetTextColor(muted)
	if r013Preview {
		note.SetText("Предпросмотр · синтетические профили · VPN не запускается")
	}
}
func addR013Footer(mtw *ManageTunnelsWindow) {
	footer, _ := walk.NewComposite(mtw)
	layout := walk.NewHBoxLayout()
	layout.SetMargins(walk.Margins{16, 4, 16, 10})
	footer.SetLayout(layout)
	label, _ := walk.NewLabel(footer)
	label.SetText("Версия " + version.Number)
	label.SetTextColor(muted)
	walk.NewHSpacer(footer)
	credit, _ := walk.NewLabel(footer)
	credit.SetText("Разработчик")
	credit.SetTextColor(muted)
	link, _ := walk.NewPushButton(footer)
	link.SetText("@R013_Support")
	link.SetMinMaxSize(walk.Size{136, 26}, walk.Size{136, 26})
	link.Clicked().Attach(func() { externalLink(mtw, r013.SupportURL) })
}
func (tp *TunnelsPage) addR013Menu(menu *walk.Menu) {
	for _, item := range []struct {
		text string
		run  func()
	}{
		{"Создать режим Авто", tp.onCreateAuto},
		{"Купить конфигурацию", func() { externalLink(tp.Form(), r013.PurchaseURL) }},
		{"1 час бесплатно", func() { externalLink(tp.Form(), r013.TrialURL) }},
	} {
		action := walk.NewAction()
		action.SetText(item.text)
		action.Triggered().Attach(item.run)
		menu.Actions().Add(action)
	}
}
func (tp *TunnelsPage) onCreateAuto() {
	if walk.MsgBox(tp.Form(), "Создать режим Авто", "Авто использует текущие профили с полным IPv4-туннелем (до 30). Ключи и исходные настройки сохраняются. После двух неудачных подключений или задержки свыше 1200 мс будет выбран следующий сервер.\n\nПродолжить?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	go func() {
		tunnels, err := manager.IPCClientTunnels()
		configs := []conf.Config{}
		if err == nil {
			for _, t := range tunnels {
				if t.Name == r013.AutoName {
					continue
				}
				c, e := t.StoredConfig()
				if e != nil {
					err = e
					break
				}
				configs = append(configs, c)
			}
		}
		if err == nil {
			err = r013.ValidateCandidates(configs)
		}
		if err == nil {
			err = manager.IPCClientCreateAuto(configs)
		}
		tp.Synchronize(func() {
			if err != nil {
				showErrorCustom(tp.Form(), "Авто не создано", err.Error())
			} else {
				tp.listView.Load(false)
				tp.listView.selectTunnel(r013.AutoName)
			}
		})
	}()
}
func (tp *TunnelsPage) onPingAll(button *walk.PushButton) {
	if tp.pingCancel != nil {
		tp.pingCancel()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	tp.pingCancel = cancel
	button.SetText("Остановить тест")
	// Auto's old endpoint result must not survive a subsequent stopped/unknown
	// membership scan. An inactive Auto has no current peer to measure.
	tp.listView.model.pings[r013.AutoName] = "—"
	for index, tunnel := range tp.listView.model.tunnels {
		if tunnel.Name == r013.AutoName {
			tp.listView.model.PublishRowChanged(index)
			break
		}
	}
	go func() {
		defer cancel()
		defer tp.Synchronize(func() { tp.pingCancel = nil; button.SetText("Проверить пинг") })
		tunnels, err := manager.IPCClientTunnels()
		if err != nil {
			return
		}
		type target struct{ name, host, identity string }
		targets := []target{}
		for _, tunnel := range tunnels {
			if ctx.Err() != nil {
				break
			}
			var c conf.Config
			var e error
			if tunnel.Name == r013.AutoName {
				state, stateErr := tunnel.State()
				if stateErr != nil || state != manager.TunnelStarted {
					continue
				}
				c, e = tunnel.RuntimeConfig()
			} else {
				c, e = tunnel.StoredConfig()
			}
			if e != nil || len(c.Peers) != 1 || c.Peers[0].Endpoint.IsEmpty() {
				continue
			}
			var pingTarget r013.CurrentPingTarget
			if tunnel.Name == r013.AutoName {
				pingTarget, e = r013.CurrentTarget(tunnel.Name, &c, nil)
			} else {
				pingTarget, e = r013.CurrentTarget(tunnel.Name, nil, &c)
			}
			if e != nil {
				continue
			}
			targets = append(targets, target{tunnel.Name, pingTarget.Host, pingTarget.Identity})
		}
		jobs := make(chan target)
		var workers sync.WaitGroup
		for i := 0; i < 3; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for item := range jobs {
					delay, e := r013.Echo(ctx, item.host, nil, 2500*time.Millisecond)
					if item.name == r013.AutoName {
						tunnel := manager.Tunnel{Name: item.name}
						state, stateErr := tunnel.State()
						live, liveErr := tunnel.RuntimeConfig()
						fresh, targetErr := r013.CurrentTarget(item.name, &live, nil)
						if stateErr != nil || state != manager.TunnelStarted || liveErr != nil || targetErr != nil || fresh.Identity != item.identity {
							continue
						}
					}
					text := "Нет ответа"
					if e == nil {
						if delay < time.Millisecond {
							text = "<1 мс"
						} else {
							text = fmt.Sprintf("%d мс", delay.Milliseconds())
						}
					} else if ctx.Err() != nil {
						text = "Отменено"
					}
					tp.Synchronize(func() {
						tp.listView.model.pings[item.name] = text
						for index, tunnel := range tp.listView.model.tunnels {
							if tunnel.Name == item.name {
								tp.listView.model.PublishRowChanged(index)
								break
							}
						}
					})
				}
			}()
		}
		for _, item := range targets {
			if ctx.Err() != nil {
				break
			}
			select {
			case jobs <- item:
			case <-ctx.Done():
			}
		}
		close(jobs)
		workers.Wait()
	}()
}
