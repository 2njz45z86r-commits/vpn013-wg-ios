//go:build r013preview

// SPDX-License-Identifier: MIT
package main

import (
	"encoding/gob"
	"github.com/amnezia-vpn/amneziawg-windows-client/manager"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/ringlogger"
	"github.com/amnezia-vpn/amneziawg-windows-client/ui"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"os"
	"path/filepath"
)

func runR013Preview() bool {
	temporary, err := os.MkdirTemp("", "vpn013-preview-")
	if err != nil {
		panic(err)
	}
	if ringlogger.Global, err = ringlogger.NewRinglogger(filepath.Join(temporary, "preview.bin"), "PREV"); err != nil {
		panic(err)
	}
	clientRead, serverWrite, _ := os.Pipe()
	serverRead, clientWrite, _ := os.Pipe()
	eventsRead, eventsWrite, _ := os.Pipe()
	go func() {
		defer clientRead.Close()
		defer serverWrite.Close()
		defer serverRead.Close()
		defer clientWrite.Close()
		defer eventsRead.Close()
		defer eventsWrite.Close()
		decoder, encoder := gob.NewDecoder(serverRead), gob.NewEncoder(serverWrite)
		profiles := []manager.Tunnel{{Name: "+Первый"}, {Name: "Finland"}, {Name: "Germany"}, {Name: "Netherlands"}, {Name: "R013-Auto"}, {Name: "Дом"}}
		scenario := os.Getenv("VPN013_PREVIEW_SCENARIO")
		activeName := ""
		if scenario == "manual" || scenario == "manual-no-stats" {
			activeName = "Finland"
		}
		if scenario == "auto" || scenario == "auto-no-stats" {
			activeName = r013.AutoName
		}
		for {
			var method manager.MethodType
			if decoder.Decode(&method) != nil {
				return
			}
			switch method {
			case manager.TunnelsMethodType:
				encoder.Encode(profiles)
				encoder.Encode("")
			case manager.StoredConfigMethodType, manager.RuntimeConfigMethodType:
				var name string
				decoder.Decode(&name)
				if method == manager.RuntimeConfigMethodType && (scenario == "manual-no-stats" || scenario == "auto-no-stats") {
					encoder.Encode(conf.Config{})
					encoder.Encode("Предпросмотр: статистика временно недоступна")
					continue
				}
				cfg, parseErr := conf.FromWgQuick("[Interface]\nPrivateKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.13.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nEndpoint = 127.0.0.1:51820\nAllowedIPs = 0.0.0.0/0\n", name)
				if parseErr != nil {
					encoder.Encode(conf.Config{})
					encoder.Encode(parseErr.Error())
					continue
				}
				encoder.Encode(*cfg)
				encoder.Encode("")
			case manager.StateMethodType:
				var name string
				decoder.Decode(&name)
				state := manager.TunnelStopped
				if name == activeName {
					state = manager.TunnelStarted
				}
				encoder.Encode(state)
				encoder.Encode("")
			case manager.GlobalStateMethodType:
				state := manager.TunnelStopped
				if activeName != "" {
					state = manager.TunnelStarted
				}
				encoder.Encode(state)
			case manager.UpdateStateMethodType:
				encoder.Encode(manager.UpdateStateUnknown)
			case manager.QuitMethodType:
				var stop bool
				decoder.Decode(&stop)
				encoder.Encode(false)
				encoder.Encode("")
			case manager.CreateAutoMethodType:
				var configs []conf.Config
				decoder.Decode(&configs)
				encoder.Encode("Предпросмотр: конфигурации не создаются.")
			case manager.CreateMethodType:
				var config conf.Config
				decoder.Decode(&config)
				encoder.Encode(manager.Tunnel{})
				encoder.Encode("Предпросмотр: конфигурации не создаются.")
			default:
				var name string
				decoder.Decode(&name)
				encoder.Encode("Предпросмотр: VPN и службы не запускаются.")
			}
		}
	}()
	manager.InitializeIPCClient(clientRead, clientWrite, eventsRead)
	ui.RunR013Preview()
	return true
}
