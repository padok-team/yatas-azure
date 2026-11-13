package vmss

import (
	"context"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v7"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// MultiZoneID is the check's unique, stable ID.
const MultiZoneID = "AZURE_VMSS_001"

// ScaleSet is a VM Scale Set.
type ScaleSet struct {
	ID    string
	Name  string
	Zones int
}

// GetScaleSets lists the scale sets of the target.
func GetScaleSets(s internal.Session) ([]ScaleSet, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armcompute.NewVirtualMachineScaleSetsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var sets []ScaleSet
	pager := client.NewListAllPager(nil)
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
			sets = append(sets, ScaleSet{ID: id, Name: internal.Deref(raw.Name), Zones: len(raw.Zones)})
		}
	}
	return sets, nil
}

// checkIfMultiZone (≈ AWS "Autoscaling groups are in multiple AZ").
func checkIfMultiZone(cfg commons.CheckConfig, in internal.Fetched[ScaleSet], id string) {
	check := internal.NewCheck("VM Scale Sets span multiple availability zones", "Check that scale sets are deployed in at least 2 availability zones", id, "Reliability", "Good Practice")
	internal.Evaluate(cfg, check, in, "VM scale sets", func(s ScaleSet) *internal.Verdict {
		if s.Zones >= 2 {
			return internal.Yes(s.ID, s.Name+" spans multiple availability zones")
		}
		return internal.No(s.ID, s.Name+" is deployed in less than 2 availability zones")
	})
}

func RunChecks(wg *sync.WaitGroup, s internal.Session, c *commons.Config, queue chan []commons.Check) {
	list, err := GetScaleSets(s)
	sets := internal.Fetch("VM scale sets", list, err)
	internal.RunCategory("VMSS", c, queue, internal.Bind(MultiZoneID, sets, checkIfMultiZone))
}
