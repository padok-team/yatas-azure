package sql

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetServers(s)
	servers := internal.Fetch("database servers", list, err)

	internal.RunCategory("SQL", c, queue,
		internal.Bind(PrivateID, servers, checkIfNotPublic),
		internal.Bind(EncryptedID, servers, checkIfEncrypted),
		internal.Bind(BackupID, servers, checkIfBackupWithPITR),
		internal.Bind(FirewallID, servers, checkIfFirewallRestricted),
		internal.Bind(AutoUpgradeID, servers, checkIfMinorVersionAutoUpdated),
		internal.Bind(LockID, servers, checkIfDeleteLock),
		internal.Bind(AuditingID, servers, checkIfAuditing),
	)
}
