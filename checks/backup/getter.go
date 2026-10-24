package backup

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservices/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v5"
	"github.com/padok-team/yatas-azure/internal"
)

// ProtectedVM is a virtual machine protected by Azure Backup.
type ProtectedVM struct {
	ID                string
	Name              string
	Vault             string
	LastRecoveryPoint time.Time // zero when there is no recovery point
}

// GetProtectedVMs lists the VMs protected by Azure Backup in every Recovery
// Services vault of the target, with the date of their last recovery point.
func GetProtectedVMs(s internal.Session) ([]ProtectedVM, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	ctx := context.TODO()
	sub := s.Target.SubscriptionID

	vaultClient, err := armrecoveryservices.NewVaultsClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	itemClient, err := armrecoveryservicesbackup.NewBackupProtectedItemsClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}

	filter := "backupManagementType eq 'AzureIaasVM' and itemType eq 'VM'"
	var vms []ProtectedVM
	vaultPager := vaultClient.NewListBySubscriptionIDPager(nil)
	for vaultPager.More() {
		page, err := vaultPager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vault := range page.Value {
			vaultID := internal.Deref(vault.ID)
			if !s.Target.InScope(vaultID) {
				continue
			}
			vaultName := internal.Deref(vault.Name)
			itemPager := itemClient.NewListPager(vaultName, internal.ResourceGroupOf(vaultID), &armrecoveryservicesbackup.BackupProtectedItemsClientListOptions{Filter: &filter})
			for itemPager.More() {
				itemPage, err := itemPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, item := range itemPage.Value {
					vm, ok := item.Properties.(interface {
						GetAzureIaaSVMProtectedItem() *armrecoveryservicesbackup.AzureIaaSVMProtectedItem
					})
					if !ok {
						continue
					}
					base := vm.GetAzureIaaSVMProtectedItem()
					p := ProtectedVM{ID: internal.Deref(item.ID), Name: internal.Deref(base.FriendlyName), Vault: vaultName}
					if base.LastRecoveryPoint != nil {
						p.LastRecoveryPoint = *base.LastRecoveryPoint
					}
					vms = append(vms, p)
				}
			}
		}
	}
	return vms, nil
}
