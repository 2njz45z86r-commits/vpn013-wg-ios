// SPDX-License-Identifier: MIT
package manager

import (
	"errors"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows-client/r013"
	"github.com/amnezia-vpn/amneziawg-windows-client/r013routing"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"golang.org/x/sys/windows"
)

var loadServicePolicies = r013routing.LoadServicePolicies
var saveServicePolicies = r013routing.SaveServicePolicies
var loadServiceConfig = conf.LoadFromName
var serviceTargetDigest = r013routing.PolicyTargetDigest
var validateAutoServices = r013routing.ValidateAutoServiceMembers

// UpdateServicePolicies checks every explicit target before the one atomic
// protected write. It never stops a tunnel or changes its quick configuration.
func (s *ManagerService) UpdateServicePolicies(changes []r013routing.ProfilePolicy) error {
	if s.elevatedToken == 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	if len(changes) == 0 || len(changes) > 90 {
		return errors.New("Выберите серверы для применения.")
	}
	autoControl.Lock()
	defer autoControl.Unlock()
	old, err := loadServicePolicies()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, change := range changes {
		name := strings.ToLower(change.Name)
		if !conf.TunnelNameIsValid(change.Name) || seen[name] {
			return errors.New("Некорректный список серверов.")
		}
		seen[name] = true
		state, e := stateR013Tunnel(s, change.Name)
		if e != nil || state != TunnelStopped {
			return errors.New("Отключите выбранный сервер и повторите применение.")
		}
		cfg, e := loadServiceConfig(change.Name)
		if e != nil {
			return errors.New("Не удалось проверить выбранный профиль.")
		}
		digest, e := serviceTargetDigest(cfg)
		if e != nil || change.SourceDigest != digest {
			return errors.New("Профиль изменился. Обновите список и повторите применение.")
		}
		if strings.EqualFold(change.Name, r013.AutoName) {
			_, e = validateAutoServices(cfg, change.Selection)
		} else {
			e = r013routing.ValidateProfileForServicePolicy(cfg, change.Selection)
		}
		if e != nil {
			return e
		}
	}
	// Replace only the specifically named bindings, preserving unrelated choices.
	next := r013routing.ServicePolicies{Version: 1}
	for _, entry := range old.Profiles {
		if !seen[strings.ToLower(entry.Name)] {
			next.Profiles = append(next.Profiles, entry)
		}
	}
	next.Profiles = append(next.Profiles, changes...)
	return saveServicePolicies(next)
}

type ServiceTarget struct {
	Name         string
	SourceDigest string
}

func (s *ManagerService) GetServiceTargets() ([]ServiceTarget, error) {
	if s.elevatedToken == 0 {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	autoControl.Lock()
	defer autoControl.Unlock()
	tunnels, err := s.Tunnels()
	if err != nil {
		return nil, err
	}
	if len(tunnels) > 90 {
		return nil, errors.New("Слишком много серверов.")
	}
	targets := make([]ServiceTarget, 0, len(tunnels))
	for _, t := range tunnels {
		cfg, e := loadServiceConfig(t.Name)
		if e != nil {
			return nil, e
		}
		digest, e := serviceTargetDigest(cfg)
		if e != nil {
			if strings.EqualFold(t.Name, r013.AutoName) {
				// Keep the logical target visible. A selected unavailable Auto
				// fails the whole transaction instead of being silently skipped.
				targets = append(targets, ServiceTarget{Name: t.Name})
				continue
			}
			return nil, e
		}
		targets = append(targets, ServiceTarget{Name: t.Name, SourceDigest: digest})
	}
	return targets, nil
}
func (s *ManagerService) GetServicePolicies() (r013routing.ServicePolicies, error) {
	if s.elevatedToken == 0 {
		return r013routing.ServicePolicies{}, windows.ERROR_ACCESS_DENIED
	}
	autoControl.Lock()
	defer autoControl.Unlock()
	return loadServicePolicies()
}
