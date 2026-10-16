package cosmosdb

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	logger.Logger.Debug("COS - Checks started")
	var checkConfig commons.CheckConfig
	checkConfig.Init(c)
	var checks []commons.Check

	list, err := GetAccounts(s)
	accounts := internal.Fetch("Cosmos DB accounts", list, err)

	go commons.CheckTest(checkConfig.Wg, c, EncryptedID, checkIfEncrypted)(checkConfig, accounts, EncryptedID)
	go commons.CheckTest(checkConfig.Wg, c, BackupID, checkIfContinuousBackup)(checkConfig, accounts, BackupID)

	go func() {
		for t := range checkConfig.Queue {
			t.EndCheck()
			checks = append(checks, t)
			checkConfig.Wg.Done()
		}
	}()

	checkConfig.Wg.Wait()

	queue <- checks
	logger.Logger.Debug("COS - Checks done")
}
