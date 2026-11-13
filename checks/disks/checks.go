package disks

import (
	"fmt"
	"strings"
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

const (
	UnusedID   = "AZURE_DSK_003"
	SKUID      = "AZURE_DSK_004"
	SnapshotID = "AZURE_DSK_005"
)

// snapshotMaxAge is how old the latest snapshot of an attached disk may be.
const snapshotMaxAge = 7 * 24 * time.Hour

// AZURE_DSK_003 (≈ AWS "EC2 volumes are in use").
func checkIfDisksInUse(cfg commons.CheckConfig, in internal.Fetched[Disk], id string) {
	check := internal.NewCheck("Managed disks are attached", "Check that managed disks are attached to a VM", id, "Cost", "Good Practice")
	internal.Evaluate(cfg, check, in, "managed disks", func(d Disk) *internal.Verdict {
		if d.Attached {
			return internal.Yes(d.ID, "Disk "+d.Name+" is attached")
		}
		return internal.No(d.ID, "Disk "+d.Name+" is not attached to any VM")
	})
}

// AZURE_DSK_004 (≈ AWS "EC2 volumes are not GP2"): Standard HDD is the legacy SKU.
func checkIfModernSKU(cfg commons.CheckConfig, in internal.Fetched[Disk], id string) {
	check := internal.NewCheck("Managed disks do not use Standard HDD", "Check that disks use SSD SKUs (Standard SSD, Premium SSD, Premium SSD v2, Ultra)", id, "Cost", "Good Practice")
	internal.Evaluate(cfg, check, in, "managed disks", func(d Disk) *internal.Verdict {
		if strings.EqualFold(d.SKU, "Standard_LRS") {
			return internal.No(d.ID, "Disk "+d.Name+" uses Standard HDD (Standard_LRS)")
		}
		return internal.Yes(d.ID, fmt.Sprintf("Disk %s uses %s", d.Name, d.SKU))
	})
}

// AZURE_DSK_005 (≈ AWS "EC2 volumes have snapshots"): attached disks need a snapshot
// younger than 7 days.
func checkIfRecentSnapshots(disks, snaps internal.Fetched[Disk]) func(commons.CheckConfig, string) {
	return func(cfg commons.CheckConfig, id string) {
		check := internal.NewCheck("Managed disks have recent snapshots", "Check that attached disks have a snapshot younger than 7 days", id, "Reliability", "Good Practice")
		if snaps.Failed(&check, "disk snapshots") {
			cfg.Queue <- check
			return
		}
		latest := map[string]time.Time{}
		for _, sn := range snaps.Items {
			k := strings.ToLower(sn.SourceID)
			if sn.Created.After(latest[k]) {
				latest[k] = sn.Created
			}
		}
		internal.Evaluate(cfg, check, disks, "managed disks", func(d Disk) *internal.Verdict {
			if !d.Attached {
				return nil
			}
			at, ok := latest[strings.ToLower(d.ID)]
			switch {
			case !ok:
				return internal.No(d.ID, "Disk "+d.Name+" has no snapshot")
			case time.Since(at) > snapshotMaxAge:
				return internal.No(d.ID, fmt.Sprintf("Latest snapshot of disk %s is %d days old", d.Name, int(time.Since(at).Hours()/24)))
			}
			return internal.Yes(d.ID, "Disk "+d.Name+" has a snapshot younger than 7 days")
		})
	}
}
