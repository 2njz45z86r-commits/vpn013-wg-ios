// SPDX-License-Identifier: MIT
package r013routing

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// Folder data contains display fields only. Opening/searching never selects a service.
type CatalogGroup struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Services []CatalogService `json:"services"`
}

func catalogGroupTitle(service CatalogService) string {
	name := strings.ToLower(service.Name)
	switch name {
	case "discord", "element", "signal", "tamtam chat", "telegram", "viber", "whatsapp", "zello":
		return "💬 Мессенджеры"
	case "4pda", "pikabu", "quora", "ru board":
		return "👥 Форумы и сообщества"
	case "vkplay":
		return "🎮 Игры и игровые платформы"
	case "cwer":
		return "📦 Прочее"
	}
	if service.Category == "📱 Социальные сети и мессенджеры" || service.Category == "💬 Соцсети и форумы" {
		return "📱 Социальные сети"
	}
	return service.Category
}

// DisplayGroups presents the supplied catalog as expandable folders. The UI
// owns expansion state; no network rule, selection or existing policy changes.
func (c *ServiceCatalog) DisplayGroups(query string) []CatalogGroup {
	if len(query) > 256 {
		return nil
	}
	query = strings.ToLower(strings.TrimSpace(query))
	folders := make(map[string][]CatalogService)
	for _, service := range c.services {
		title := catalogGroupTitle(service)
		if query != "" && !strings.Contains(strings.ToLower(service.Name), query) && !strings.Contains(strings.ToLower(title), query) {
			continue
		}
		folders[title] = append(folders[title], service)
	}
	groups := make([]CatalogGroup, 0, len(folders))
	for title, services := range folders {
		sort.Slice(services, func(i, j int) bool { return strings.ToLower(services[i].Name) < strings.ToLower(services[j].Name) })
		digest := sha256.Sum256([]byte(title))
		groups = append(groups, CatalogGroup{fmt.Sprintf("grp_%x", digest[:8]), title, services})
	}
	priority := map[string]int{"📱 Социальные сети": 1, "💬 Мессенджеры": 2, "👥 Форумы и сообщества": 3,
		"📺 Медиа-платформы": 4, "🎬 Развлечения, кино и ТВ": 5, "🎮 Игры и игровые платформы": 6}
	sort.Slice(groups, func(i, j int) bool {
		a, b := priority[groups[i].Title], priority[groups[j].Title]
		if a == 0 {
			a = 100
		}
		if b == 0 {
			b = 100
		}
		if a != b {
			return a < b
		}
		return groups[i].Title < groups[j].Title
	})
	return groups
}
