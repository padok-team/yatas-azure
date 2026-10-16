package internal

import (
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

// UnmarshalConfig decodes the plugin configuration YATAS reads from `.yatas.yml`
// into the list of subscriptions to audit.
//
// YATAS hands every plugin's config to every plugin, so we first pick the block
// whose `pluginName` matches ours, then turn each entry under `accounts` into a
// Target.
func UnmarshalConfig(c *commons.Config) ([]Target, error) {
	var targets []Target

	var pluginConfig map[string]interface{}
	for _, config := range c.PluginConfig {
		if config["pluginName"] == PluginName {
			pluginConfig = config
		}
	}
	if pluginConfig == nil {
		logger.Logger.Error("No configuration found for plugin", "plugin", PluginName)
		return targets, nil
	}

	accounts, ok := pluginConfig["accounts"].([]interface{})
	if !ok {
		logger.Logger.Error("No `accounts` list found in plugin config")
		return targets, nil
	}

	for _, entry := range accounts {
		fields, ok := entry.(map[string]interface{})
		if !ok {
			continue
		}

		var target Target
		for key, value := range fields {
			switch key {
			case "name":
				target.Name, _ = value.(string)
			case "subscription_id":
				target.SubscriptionID, _ = value.(string)
			case "tenant_id":
				target.TenantID, _ = value.(string)
			case "resource_group":
				target.ResourceGroup, _ = value.(string)
			default:
				logger.Logger.Warn("Unknown field in target config", "field", key)
			}
		}
		if target.SubscriptionID == "" {
			logger.Logger.Error("Target ignored: `subscription_id` is required", "target", target.Name)
			continue
		}
		if target.Name == "" {
			target.Name = target.SubscriptionID
		}
		targets = append(targets, target)
	}

	logger.Logger.Debug("Targets to audit", "targets", targets)
	return targets, nil
}
