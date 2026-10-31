package r013routing

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDisplayFoldersAreSeparateFromRoutesAndChoices(t *testing.T) {
	c := catalogFixture(t)
	groups := c.DisplayGroups("")
	if len(groups) != 1 || len(groups[0].Services) != 2 {
		t.Fatal("display lost services")
	}
	if len(c.DisplayGroups("ALPHA")) != 1 || len(c.DisplayGroups("no matching service")) != 0 {
		t.Fatal("global name search failed")
	}
	encoded, err := json.Marshal(groups)
	if err != nil || strings.Contains(string(encoded), "alpha.example.invalid") || strings.Contains(string(encoded), "8.8.8.") {
		t.Fatal("display leaked technical rules")
	}
	plan, err := c.Resolve(ServiceSelection{})
	if err != nil || plan != nil {
		t.Fatal("opening folder applied routing")
	}
}

func TestMessagingSocialAndForumsHaveDistinctFolders(t *testing.T) {
	c := &ServiceCatalog{services: []CatalogService{
		{ID: serviceA, Name: "Telegram", Category: "📱 Социальные сети и мессенджеры"},
		{ID: serviceB, Name: "Instagram", Category: "📱 Социальные сети и мессенджеры"},
		{ID: "svc_0000000000000003", Name: "4PDA", Category: "💬 Соцсети и форумы"},
	}}
	groups := c.DisplayGroups("")
	if len(groups) != 3 || groups[0].Title != "📱 Социальные сети" || groups[1].Title != "💬 Мессенджеры" || groups[2].Title != "👥 Форумы и сообщества" {
		t.Fatal("communications not separated")
	}
	if groups[0].Services[0].Name != "Instagram" || groups[1].Services[0].Name != "Telegram" || groups[2].Services[0].Name != "4PDA" {
		t.Fatal("wrong service membership")
	}
	if len(c.DisplayGroups("Мессенджеры")) != 1 {
		t.Fatal("group title search failed")
	}
}
