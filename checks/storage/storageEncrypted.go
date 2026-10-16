package storage

import (
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// EncryptedID is the check's unique, stable ID.
const EncryptedID = "AZURE_STO_001"

// checkIfEncrypted (≈ AWS "S3 are encrypted"). Azure always encrypts at rest with
// Microsoft-managed keys, so an HDS-grade check requires more: services encrypted
// AND a customer-managed key or infrastructure (double) encryption.
func checkIfEncrypted(checkConfig commons.CheckConfig, accounts internal.Fetched[Account], testName string) {
	check := internal.NewHDSCheck("Storage accounts are encrypted", "Check that storage accounts are encrypted at rest with a customer-managed key or infrastructure (double) encryption", testName)
	if accounts.Failed(&check, "storage accounts") {
		checkConfig.Queue <- check
		return
	}
	for _, a := range accounts.Items {
		switch {
		case !a.ServicesEncrypted:
			internal.Fail(&check, a.ID, "Encryption at rest is not enabled for the blob and file services of "+a.Name)
		case a.CustomerManagedKey:
			internal.Pass(&check, a.ID, "Storage account "+a.Name+" is encrypted with a customer-managed key")
		case a.InfrastructureEncryption:
			internal.Pass(&check, a.ID, "Storage account "+a.Name+" has infrastructure (double) encryption enabled")
		default:
			internal.Fail(&check, a.ID, "Storage account "+a.Name+" only uses Microsoft-managed keys without infrastructure encryption")
		}
	}
	checkConfig.Queue <- check
}
