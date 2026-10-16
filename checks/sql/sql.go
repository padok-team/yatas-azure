package sql

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	logger.Logger.Debug("SQL - Checks started")
	var checkConfig commons.CheckConfig
	checkConfig.Init(c)
	var checks []commons.Check

	list, err := GetServers(s)
	servers := internal.Fetch("database servers", list, err)

	go commons.CheckTest(checkConfig.Wg, c, PrivateID, checkIfNotPublic)(checkConfig, servers, PrivateID)
	go commons.CheckTest(checkConfig.Wg, c, EncryptedID, checkIfEncrypted)(checkConfig, servers, EncryptedID)
	go commons.CheckTest(checkConfig.Wg, c, BackupID, checkIfBackupWithPITR)(checkConfig, servers, BackupID)
	go commons.CheckTest(checkConfig.Wg, c, FirewallID, checkIfFirewallRestricted)(checkConfig, servers, FirewallID)
	go commons.CheckTest(checkConfig.Wg, c, AutoUpgradeID, checkIfMinorVersionAutoUpdated)(checkConfig, servers, AutoUpgradeID)

	go func() {
		for t := range checkConfig.Queue {
			t.EndCheck()
			checks = append(checks, t)
			checkConfig.Wg.Done()
		}
	}()

	checkConfig.Wg.Wait()

	queue <- checks
	logger.Logger.Debug("SQL - Checks done")
}
