package backup

import (
	"sync"
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	logger.Logger.Debug("BCK - Checks started")
	var checkConfig commons.CheckConfig
	checkConfig.Init(c)
	var checks []commons.Check

	list, err := GetProtectedVMs(s)
	vms := internal.Fetch("Azure Backup protected VMs", list, err)

	go commons.CheckTest(checkConfig.Wg, c, RecoveryPoint24hID, checkNow)(checkConfig, vms, RecoveryPoint24hID)

	go func() {
		for t := range checkConfig.Queue {
			t.EndCheck()
			checks = append(checks, t)
			checkConfig.Wg.Done()
		}
	}()

	checkConfig.Wg.Wait()

	queue <- checks
	logger.Logger.Debug("BCK - Checks done")
}

// checkNow binds the real clock to the check so it fits commons.CheckTest.
func checkNow(checkConfig commons.CheckConfig, vms internal.Fetched[ProtectedVM], testName string) {
	checkIfRecoveryPointLessThan24h(checkConfig, vms, testName, time.Now)
}
