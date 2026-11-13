package defender

import (
	"strings"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// NoHighAlertsID is the check's unique, stable ID.
const NoHighAlertsID = "AZURE_DEF_003"

// checkIfNoHighAlerts (≈ AWS "GuardDuty has no HIGH severity findings"). One
// result per active high-severity alert, or a single OK when there is none.
func checkIfNoHighAlerts(cfg commons.CheckConfig, in internal.Fetched[Alert], id string) {
	check := internal.NewCheck("Defender for Cloud has no active high severity alerts", "Check that no high severity security alert is active", id)
	if !in.Failed(&check, "Defender for Cloud alerts") {
		found := false
		for _, a := range in.Items {
			if strings.EqualFold(a.Severity, "High") && (a.Status == "" || strings.EqualFold(a.Status, "Active")) {
				found = true
				internal.Fail(&check, a.ID, "Active high severity alert: "+a.Name)
			}
		}
		if !found {
			internal.Pass(&check, "", "No active high severity alert")
		}
	}
	cfg.Queue <- check
}
