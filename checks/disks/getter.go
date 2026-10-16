package disks

import (
	"context"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/padok-team/yatas-azure/internal"
)

// Disk is a managed disk or a snapshot with its encryption-at-rest type.
type Disk struct {
	ID       string
	Name     string
	Snapshot bool
	// EncryptionType is the SSE type, e.g. EncryptionAtRestWithPlatformKey,
	// EncryptionAtRestWithCustomerKey, EncryptionAtRestWithPlatformAndCustomerKeys.
	EncryptionType string
}

// CustomerManaged reports whether a customer-managed key is involved.
func (d Disk) CustomerManaged() bool {
	return strings.Contains(d.EncryptionType, "CustomerKey") || strings.Contains(d.EncryptionType, "CustomerKeys")
}

// GetDisks lists the managed disks of the target.
func GetDisks(s internal.Session) ([]Disk, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armcompute.NewDisksClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var disks []Disk
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
			d := Disk{ID: id, Name: internal.Deref(raw.Name)}
			if raw.Properties != nil && raw.Properties.Encryption != nil && raw.Properties.Encryption.Type != nil {
				d.EncryptionType = string(*raw.Properties.Encryption.Type)
			}
			disks = append(disks, d)
		}
	}
	return disks, nil
}

// GetSnapshots lists the disk snapshots of the target.
func GetSnapshots(s internal.Session) ([]Disk, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armcompute.NewSnapshotsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var snapshots []Disk
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
			d := Disk{ID: id, Name: internal.Deref(raw.Name), Snapshot: true}
			if raw.Properties != nil && raw.Properties.Encryption != nil && raw.Properties.Encryption.Type != nil {
				d.EncryptionType = string(*raw.Properties.Encryption.Type)
			}
			snapshots = append(snapshots, d)
		}
	}
	return snapshots, nil
}
