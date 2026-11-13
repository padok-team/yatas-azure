package cosmosdb

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetAccounts(s)
	accounts := internal.Fetch("Cosmos DB accounts", list, err)
	containerList, err := GetContainers(s)
	containers := internal.Fetch("Cosmos DB containers", containerList, err)

	internal.RunCategory("COS", c, queue,
		internal.Bind(EncryptedID, accounts, checkIfEncrypted),
		internal.Bind(BackupID, accounts, checkIfContinuousBackup),
		internal.Bind(TTLID, containers, checkIfTTL),
	)
}
