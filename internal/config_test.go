package internal

import (
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func TestUnmarshalConfig(t *testing.T) {
	logger.Logger = hclog.NewNullLogger()
	c := &commons.Config{PluginConfig: []map[string]interface{}{
		{"pluginName": "aws", "accounts": []interface{}{map[string]interface{}{"name": "ignored"}}},
		{"pluginName": "azure", "accounts": []interface{}{
			map[string]interface{}{"name": "prod", "subscription_id": "sub-1", "tenant_id": "ten", "resource_group": "rg"},
			map[string]interface{}{"subscription_id": "sub-2"},
			map[string]interface{}{"name": "no-subscription"},
		}},
	}}
	targets, err := UnmarshalConfig(c)
	if err != nil || len(targets) != 2 {
		t.Fatalf("targets = %+v, err = %v", targets, err)
	}
	if targets[0] != (Target{Name: "prod", SubscriptionID: "sub-1", TenantID: "ten", ResourceGroup: "rg"}) {
		t.Errorf("unexpected first target: %+v", targets[0])
	}
	if targets[1].Name != "sub-2" {
		t.Errorf("name should default to the subscription ID, got %q", targets[1].Name)
	}
}

func TestInScope(t *testing.T) {
	id := "/subscriptions/s/resourceGroups/My-RG/providers/Microsoft.Storage/storageAccounts/a"
	if !(Target{}).InScope(id) || !(Target{ResourceGroup: "my-rg"}).InScope(id) {
		t.Error("resource should be in scope")
	}
	if (Target{ResourceGroup: "other"}).InScope(id) {
		t.Error("resource of another resource group should be out of scope")
	}
}
