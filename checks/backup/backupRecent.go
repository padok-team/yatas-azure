package backup

import (
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// RecoveryPoint24hID is the check's unique, stable ID.
const RecoveryPoint24hID = "AZURE_BCK_001"

// checkIfRecoveryPointLessThan24h (≈ AWS "EC2's snapshots are younger than a day
// old"): every VM protected by Azure Backup has a recovery point from the last
// 24 hours. `now` is injected so the check is deterministic in tests.
func checkIfRecoveryPointLessThan24h(checkConfig commons.CheckConfig, vms internal.Fetched[ProtectedVM], testName string, now func() time.Time) {
	check := internal.NewHDSCheck("VM backups are younger than a day old", "Check that every VM protected by Azure Backup has a recovery point from the last 24 hours", testName)
	if vms.Failed(&check, "Azure Backup protected VMs") {
		checkConfig.Queue <- check
		return
	}
	for _, vm := range vms.Items {
		switch {
		case vm.LastRecoveryPoint.IsZero():
			internal.Fail(&check, vm.ID, "VM "+vm.Name+" has no recovery point in vault "+vm.Vault)
		case now().Sub(vm.LastRecoveryPoint) > 24*time.Hour:
			internal.Fail(&check, vm.ID, "Last recovery point of VM "+vm.Name+" is older than 24h ("+vm.LastRecoveryPoint.Format(time.RFC3339)+")")
		default:
			internal.Pass(&check, vm.ID, "VM "+vm.Name+" has a recovery point younger than 24h")
		}
	}
	checkConfig.Queue <- check
}
