package disks

import (
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

const (
	DisksEncryptedID     = "AZURE_DSK_001"
	SnapshotsEncryptedID = "AZURE_DSK_002"
)

// checkIfDisksEncrypted (≈ AWS "EC2's volumes are encrypted"). SSE with a
// platform key is always on in Azure; HDS-grade requires a customer-managed key.
func checkIfDisksEncrypted(checkConfig commons.CheckConfig, disks internal.Fetched[Disk], testName string) {
	check := internal.NewHDSCheck("Managed disks are encrypted", "Check that managed disks are encrypted at rest with a customer-managed key", testName)
	evaluate(&check, disks, "managed disks", "Disk")
	checkConfig.Queue <- check
}

// checkIfSnapshotsEncrypted (≈ AWS "EC2's Snapshots are encrypted").
func checkIfSnapshotsEncrypted(checkConfig commons.CheckConfig, snapshots internal.Fetched[Disk], testName string) {
	check := internal.NewHDSCheck("Disk snapshots are encrypted", "Check that disk snapshots are encrypted at rest with a customer-managed key", testName)
	evaluate(&check, snapshots, "disk snapshots", "Snapshot")
	checkConfig.Queue <- check
}

func evaluate(check *commons.Check, disks internal.Fetched[Disk], what, label string) {
	if disks.Failed(check, what) {
		return
	}
	for _, d := range disks.Items {
		switch {
		case d.EncryptionType == "":
			internal.Fail(check, d.ID, label+" "+d.Name+" has no encryption at rest information")
		case d.CustomerManaged():
			internal.Pass(check, d.ID, label+" "+d.Name+" is encrypted with a customer-managed key ("+d.EncryptionType+")")
		default:
			internal.Fail(check, d.ID, label+" "+d.Name+" only uses a platform-managed key ("+d.EncryptionType+")")
		}
	}
}
