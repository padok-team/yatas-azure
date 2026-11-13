package defender

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	planList, err := GetPlans(s)
	plans := internal.Fetch("Defender for Cloud plans", planList, err)
	assignmentList, err := GetPolicyAssignments(s)
	assignments := internal.Fetch("Azure Policy assignments", assignmentList, err)
	alertList, err := GetAlerts(s)
	alerts := internal.Fetch("Defender for Cloud alerts", alertList, err)

	internal.RunCategory("DEF", c, queue,
		internal.Bind(ThreatProtectionID, plans, checkIfThreatProtectionEnabled),
		internal.Bind(PolicyID, assignments, checkIfPolicyEnabled),
		internal.Bind(NoHighAlertsID, alerts, checkIfNoHighAlerts),
	)
}
