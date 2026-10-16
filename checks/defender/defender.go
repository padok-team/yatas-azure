package defender

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	logger.Logger.Debug("DEF - Checks started")
	var checkConfig commons.CheckConfig
	checkConfig.Init(c)
	var checks []commons.Check

	planList, err := GetPlans(s)
	plans := internal.Fetch("Defender for Cloud plans", planList, err)
	assignmentList, err := GetPolicyAssignments(s)
	assignments := internal.Fetch("Azure Policy assignments", assignmentList, err)

	go commons.CheckTest(checkConfig.Wg, c, ThreatProtectionID, checkIfThreatProtectionEnabled)(checkConfig, plans, ThreatProtectionID)
	go commons.CheckTest(checkConfig.Wg, c, PolicyID, checkIfPolicyEnabled)(checkConfig, assignments, PolicyID)

	go func() {
		for t := range checkConfig.Queue {
			t.EndCheck()
			checks = append(checks, t)
			checkConfig.Wg.Done()
		}
	}()

	checkConfig.Wg.Wait()

	queue <- checks
	logger.Logger.Debug("DEF - Checks done")
}
