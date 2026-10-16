package defender

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/padok-team/yatas-azure/internal"
)

// Plan is a Microsoft Defender for Cloud plan (one entry of Microsoft.Security/pricings).
type Plan struct {
	Name     string
	Standard bool // pricingTier == Standard, i.e. the plan is on
}

// GetPlans lists the Defender for Cloud plans of the subscription.
func GetPlans(s internal.Session) ([]Plan, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armsecurity.NewPricingsClient(s.Credential, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.List(context.TODO(), internal.SubscriptionScope(s.Target.SubscriptionID), nil)
	if err != nil {
		return nil, err
	}
	var plans []Plan
	for _, p := range res.Value {
		plan := Plan{Name: internal.Deref(p.Name)}
		if p.Properties != nil && p.Properties.PricingTier != nil {
			plan.Standard = *p.Properties.PricingTier == armsecurity.PricingTierStandard
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// PolicyAssignment is an Azure Policy assignment effective on the subscription.
type PolicyAssignment struct {
	ID          string
	DisplayName string
}

// GetPolicyAssignments lists the Azure Policy assignments applying to the
// subscription (including those inherited from management groups).
func GetPolicyAssignments(s internal.Session) ([]PolicyAssignment, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armpolicy.NewAssignmentsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var assignments []PolicyAssignment
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, a := range page.Value {
			pa := PolicyAssignment{ID: internal.Deref(a.ID), DisplayName: internal.Deref(a.Name)}
			if a.Properties != nil && a.Properties.DisplayName != nil {
				pa.DisplayName = *a.Properties.DisplayName
			}
			assignments = append(assignments, pa)
		}
	}
	return assignments, nil
}
