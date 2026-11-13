package activitylog

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// ExportID is the check's unique, stable ID.
const ExportID = "AZURE_ACT_001"

// Subscription is the Activity Log export posture of the audited subscription.
type Subscription struct {
	ID       string
	Exported bool // Administrative + Security categories shipped to a destination
}

// GetSubscription reads the subscription-level diagnostic settings.
func GetSubscription(s internal.Session) ([]Subscription, error) {
	scope := internal.SubscriptionScope(s.Target.SubscriptionID)
	settings, err := internal.GetDiagnosticSettings(s, scope)
	if err != nil {
		return nil, err
	}
	return []Subscription{{ID: scope, Exported: internal.LogsShipped(settings, "Administrative") && internal.LogsShipped(settings, "Security")}}, nil
}

// checkIfExported (≈ AWS "Cloudtrail logs are exported"): the Activity Log is only
// kept 90 days unless a diagnostic setting exports it.
func checkIfExported(cfg commons.CheckConfig, in internal.Fetched[Subscription], id string) {
	check := internal.NewCheck("Activity Log is exported", "Check that the subscription Activity Log (Administrative and Security categories) is exported to a workspace, storage account or event hub", id)
	internal.Evaluate(cfg, check, in, "the Activity Log diagnostic settings", func(s Subscription) *internal.Verdict {
		if s.Exported {
			return internal.Yes(s.ID, "The Activity Log is exported")
		}
		return internal.No(s.ID, "The Activity Log is not exported: Administrative and Security categories must be sent to a destination")
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetSubscription(s)
	subs := internal.Fetch("Activity Log settings", list, err)
	internal.RunCategory("ACT", c, queue, internal.Bind(ExportID, subs, checkIfExported))
}
