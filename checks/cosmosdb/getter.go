package cosmosdb

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/padok-team/yatas-azure/internal"
)

// Account is the encryption and backup posture of one Cosmos DB account.
type Account struct {
	ID   string
	Name string
	// CustomerManagedKey is true when a Key Vault key is configured.
	CustomerManagedKey bool
	// ContinuousBackup is true when the backup policy is continuous (PITR).
	ContinuousBackup bool
}

// GetAccounts lists the Cosmos DB accounts of the target.
func GetAccounts(s internal.Session) ([]Account, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armcosmos.NewDatabaseAccountsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var accounts []Account
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			id := internal.Deref(raw.ID)
			if !s.Target.InScope(id) {
				continue
			}
			a := Account{ID: id, Name: internal.Deref(raw.Name)}
			if p := raw.Properties; p != nil {
				a.CustomerManagedKey = internal.Deref(p.KeyVaultKeyURI) != ""
				if p.BackupPolicy != nil {
					bp := p.BackupPolicy.GetBackupPolicy()
					a.ContinuousBackup = bp != nil && bp.Type != nil && *bp.Type == armcosmos.BackupPolicyTypeContinuous
				}
			}
			accounts = append(accounts, a)
		}
	}
	return accounts, nil
}
