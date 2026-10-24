package storage

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"github.com/padok-team/yatas-azure/internal"
)

// Account is the encryption posture of one storage account.
type Account struct {
	ID   string
	Name string
	// CustomerManagedKey is true when the account is encrypted with a key held in
	// Key Vault (KeySource == Microsoft.Keyvault).
	CustomerManagedKey bool
	// InfrastructureEncryption is true when double encryption is enabled.
	InfrastructureEncryption bool
	// ServicesEncrypted is true when blob and file services are encrypted.
	ServicesEncrypted bool
}

// GetAccounts lists the storage accounts of the target.
func GetAccounts(s internal.Session) ([]Account, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armstorage.NewAccountsClient(s.Target.SubscriptionID, s.Credential, nil)
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
			if raw.Properties != nil && raw.Properties.Encryption != nil {
				enc := raw.Properties.Encryption
				a.CustomerManagedKey = enc.KeySource != nil && *enc.KeySource == armstorage.KeySourceMicrosoftKeyvault
				a.InfrastructureEncryption = internal.Deref(enc.RequireInfrastructureEncryption)
				if enc.Services != nil {
					blob := enc.Services.Blob != nil && internal.Deref(enc.Services.Blob.Enabled)
					file := enc.Services.File != nil && internal.Deref(enc.Services.File.Enabled)
					a.ServicesEncrypted = blob && file
				}
			}
			accounts = append(accounts, a)
		}
	}
	return accounts, nil
}
