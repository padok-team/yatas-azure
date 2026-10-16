package internal

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

// Assignee is an identity holding at least one role assignment that applies to
// the audited subscription (assigned on the subscription, above it, or on any
// resource group or resource inside it).
type Assignee struct {
	ID   string // Entra object ID
	Type string // User, Group, ServicePrincipal, ForeignGroup, Device
}

// GetAssignees lists the distinct identities with access to the subscription.
// The IAM checks use it to evaluate only the identities that matter for this
// subscription instead of the whole Entra tenant.
func GetAssignees(s Session) ([]Assignee, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armauthorization.NewRoleAssignmentsClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var assignees []Assignee
	pager := client.NewListForSubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, err
		}
		for _, a := range page.Value {
			if a.Properties == nil || a.Properties.PrincipalID == nil || seen[*a.Properties.PrincipalID] {
				continue
			}
			seen[*a.Properties.PrincipalID] = true
			ptype := ""
			if a.Properties.PrincipalType != nil {
				ptype = string(*a.Properties.PrincipalType)
			}
			assignees = append(assignees, Assignee{ID: *a.Properties.PrincipalID, Type: ptype})
		}
	}
	return assignees, nil
}
