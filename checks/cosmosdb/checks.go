package cosmosdb

import (
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	EncryptedID = "AZURE_COS_001"
	BackupID    = "AZURE_COS_002"
)

// checkIfEncrypted (≈ AWS "Dynamodbs are encrypted"). Cosmos DB always encrypts
// at rest with service-managed keys; HDS-grade requires a customer-managed key.
func checkIfEncrypted(checkConfig commons.CheckConfig, accounts internal.Fetched[Account], testName string) {
	check := internal.NewHDSCheck("Cosmos DB accounts are encrypted", "Check that Cosmos DB accounts are encrypted at rest with a customer-managed key", testName)
	if accounts.Failed(&check, "Cosmos DB accounts") {
		checkConfig.Queue <- check
		return
	}
	for _, a := range accounts.Items {
		if a.CustomerManagedKey {
			internal.Pass(&check, a.ID, "Cosmos DB account "+a.Name+" is encrypted with a customer-managed key")
		} else {
			internal.Fail(&check, a.ID, "Cosmos DB account "+a.Name+" only uses a service-managed key")
		}
	}
	checkConfig.Queue <- check
}

// checkIfContinuousBackup (≈ AWS "Dynamodb have continuous backup enabled with PITR").
func checkIfContinuousBackup(checkConfig commons.CheckConfig, accounts internal.Fetched[Account], testName string) {
	check := internal.NewHDSCheck("Cosmos DB have continuous backup enabled with PITR", "Check that Cosmos DB accounts use the continuous backup policy (point-in-time restore)", testName)
	if accounts.Failed(&check, "Cosmos DB accounts") {
		checkConfig.Queue <- check
		return
	}
	for _, a := range accounts.Items {
		if a.ContinuousBackup {
			internal.Pass(&check, a.ID, "Cosmos DB account "+a.Name+" has continuous backup enabled")
		} else {
			internal.Fail(&check, a.ID, "Cosmos DB account "+a.Name+" does not use continuous backup")
		}
	}
	checkConfig.Queue <- check
}
