package storage

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

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

	SKU              string // e.g. Standard_GRS
	PublicBlobAccess bool
	HTTPSOnly        bool
	MinTLS12         bool
	Immutability     bool // account-level immutability with versioning
	BlobProps        bool // true when the blob service could be read (the account supports blobs)
	SoftDelete       bool
	Versioning       bool
	LifecyclePolicy  bool
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
	blobs, err := armstorage.NewBlobServicesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	policies, err := armstorage.NewManagementPoliciesClient(s.Target.SubscriptionID, s.Credential, nil)
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
			if raw.SKU != nil && raw.SKU.Name != nil {
				a.SKU = string(*raw.SKU.Name)
			}
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
			if p := raw.Properties; p != nil {
				a.PublicBlobAccess = internal.Deref(p.AllowBlobPublicAccess)
				a.HTTPSOnly = internal.Deref(p.EnableHTTPSTrafficOnly)
				a.MinTLS12 = p.MinimumTLSVersion != nil && *p.MinimumTLSVersion != armstorage.MinimumTLSVersionTLS10 && *p.MinimumTLSVersion != armstorage.MinimumTLSVersionTLS11
				a.Immutability = p.ImmutableStorageWithVersioning != nil && internal.Deref(p.ImmutableStorageWithVersioning.Enabled)
			}
			if err := enrichBlob(client, blobs, policies, &a); err != nil {
				return nil, err
			}
			accounts = append(accounts, a)
		}
	}
	return accounts, nil
}

// enrichBlob reads the blob service settings and the lifecycle policy of an
// account. Accounts without a blob service (FileStorage...) are left with
// BlobProps=false so the blob checks skip them.
func enrichBlob(_ *armstorage.AccountsClient, blobs *armstorage.BlobServicesClient, policies *armstorage.ManagementPoliciesClient, a *Account) error {
	rg := internal.ResourceGroupOf(a.ID)
	svc, err := blobs.GetServiceProperties(context.TODO(), rg, a.Name, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusBadRequest || respErr.StatusCode == http.StatusNotFound) {
			return nil
		}
		return err
	}
	a.BlobProps = true
	if p := svc.BlobServiceProperties.BlobServiceProperties; p != nil {
		a.SoftDelete = p.DeleteRetentionPolicy != nil && internal.Deref(p.DeleteRetentionPolicy.Enabled)
		a.Versioning = internal.Deref(p.IsVersioningEnabled)
	}
	_, err = policies.Get(context.TODO(), rg, a.Name, armstorage.ManagementPolicyNameDefault, nil)
	var respErr *azcore.ResponseError
	switch {
	case err == nil:
		a.LifecyclePolicy = true
	case errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound:
	default:
		return err
	}
	return nil
}
