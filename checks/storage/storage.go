package storage

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetAccounts(s)
	accounts := internal.Fetch("storage accounts", list, err)

	internal.RunCategory("STO", c, queue,
		internal.Bind(EncryptedID, accounts, checkIfEncrypted),
		internal.Bind(SoftDeleteID, accounts, checkIfSoftDelete),
		internal.Bind(GeoReplID, accounts, checkIfGeoReplicated),
		internal.Bind(LifecycleID, accounts, checkIfLifecyclePolicy),
		internal.Bind(ImmutabilityID, accounts, checkIfImmutability),
		internal.Bind(PublicAccessID, accounts, checkIfNoPublicAccess),
		internal.Bind(TransportID, accounts, checkIfSecureTransport),
	)
}
