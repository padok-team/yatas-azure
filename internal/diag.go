package internal

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
)

// DiagSetting is a diagnostic setting reduced to what the log checks need.
type DiagSetting struct {
	Name string
	// HasDestination is true when logs go to a Log Analytics workspace, a
	// storage account or an event hub.
	HasDestination bool
	// Logs lists the enabled log categories and category groups, lower-cased.
	Logs []string
}

// GetDiagnosticSettings lists the diagnostic settings of an ARM resource (or of a
// subscription, with "/subscriptions/<id>" as URI).
func GetDiagnosticSettings(s Session, resourceURI string) ([]DiagSetting, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armmonitor.NewDiagnosticSettingsClient(s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var settings []DiagSetting
	pager := client.NewListPager(resourceURI, nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			d := DiagSetting{Name: Deref(raw.Name)}
			if p := raw.Properties; p != nil {
				d.HasDestination = Deref(p.WorkspaceID) != "" || Deref(p.StorageAccountID) != "" || Deref(p.EventHubAuthorizationRuleID) != ""
				for _, l := range p.Logs {
					if !Deref(l.Enabled) {
						continue
					}
					if c := Deref(l.Category); c != "" {
						d.Logs = append(d.Logs, strings.ToLower(c))
					}
					if g := Deref(l.CategoryGroup); g != "" {
						d.Logs = append(d.Logs, strings.ToLower(g))
					}
				}
			}
			settings = append(settings, d)
		}
	}
	return settings, nil
}

// LogsShipped reports whether at least one setting sends logs to a destination.
// With categories, one of them (or the "allLogs" group) must be enabled;
// without, any enabled log counts.
func LogsShipped(settings []DiagSetting, categories ...string) bool {
	for _, d := range settings {
		if !d.HasDestination {
			continue
		}
		if len(categories) == 0 && len(d.Logs) > 0 {
			return true
		}
		for _, l := range d.Logs {
			if l == "alllogs" {
				return true
			}
			for _, c := range categories {
				if l == strings.ToLower(c) {
					return true
				}
			}
		}
	}
	return false
}
