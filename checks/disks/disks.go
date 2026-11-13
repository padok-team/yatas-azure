package disks

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	diskList, err := GetDisks(s)
	disks := internal.Fetch("managed disks", diskList, err)
	snapList, err := GetSnapshots(s)
	snapshots := internal.Fetch("disk snapshots", snapList, err)

	internal.RunCategory("DSK", c, queue,
		internal.Bind(DisksEncryptedID, disks, checkIfDisksEncrypted),
		internal.Bind(SnapshotsEncryptedID, snapshots, checkIfSnapshotsEncrypted),
		internal.Bind(UnusedID, disks, checkIfDisksInUse),
		internal.Bind(SKUID, disks, checkIfModernSKU),
		internal.Entry{ID: SnapshotID, Run: checkIfRecentSnapshots(disks, snapshots)},
	)
}
