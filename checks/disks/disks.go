package disks

import (
	"sync"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas-azure/logger"
	"github.com/padok-team/yatas/plugins/commons"
)

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	logger.Logger.Debug("DSK - Checks started")
	var checkConfig commons.CheckConfig
	checkConfig.Init(c)
	var checks []commons.Check

	diskList, err := GetDisks(s)
	disks := internal.Fetch("managed disks", diskList, err)
	snapList, err := GetSnapshots(s)
	snapshots := internal.Fetch("disk snapshots", snapList, err)

	go commons.CheckTest(checkConfig.Wg, c, DisksEncryptedID, checkIfDisksEncrypted)(checkConfig, disks, DisksEncryptedID)
	go commons.CheckTest(checkConfig.Wg, c, SnapshotsEncryptedID, checkIfSnapshotsEncrypted)(checkConfig, snapshots, SnapshotsEncryptedID)

	go func() {
		for t := range checkConfig.Queue {
			t.EndCheck()
			checks = append(checks, t)
			checkConfig.Wg.Done()
		}
	}()

	checkConfig.Wg.Wait()

	queue <- checks
	logger.Logger.Debug("DSK - Checks done")
}
