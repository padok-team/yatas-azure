package aks

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v6"
	"github.com/padok-team/yatas-azure/internal"
)

// Cluster is the API-server exposure of one AKS cluster.
type Cluster struct {
	ID                 string
	Name               string
	Private            bool
	AuthorizedIPRanges []string
}

// GetClusters lists the AKS clusters of the target.
func GetClusters(s internal.Session) ([]Cluster, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	client, err := armcontainerservice.NewManagedClustersClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var clusters []Cluster
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
			c := Cluster{ID: id, Name: internal.Deref(raw.Name)}
			if raw.Properties != nil && raw.Properties.APIServerAccessProfile != nil {
				p := raw.Properties.APIServerAccessProfile
				c.Private = internal.Deref(p.EnablePrivateCluster)
				for _, r := range p.AuthorizedIPRanges {
					c.AuthorizedIPRanges = append(c.AuthorizedIPRanges, internal.Deref(r))
				}
			}
			clusters = append(clusters, c)
		}
	}
	return clusters, nil
}
