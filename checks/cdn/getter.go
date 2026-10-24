package cdn

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cdn/armcdn/v3"
	"github.com/padok-team/yatas-azure/internal"
)

// Entrypoint is an HTTP(S) entrypoint of a CDN or Front Door profile: a classic
// CDN endpoint, or a Front Door Standard/Premium route.
type Entrypoint struct {
	ID   string
	Name string
	// HTTPSOnly is true when plain HTTP is disabled or redirected to HTTPS.
	HTTPSOnly bool
}

// GetEntrypoints lists the CDN endpoints and Front Door routes of the target.
func GetEntrypoints(s internal.Session) ([]Entrypoint, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	ctx := context.TODO()
	sub := s.Target.SubscriptionID
	profiles, err := armcdn.NewProfilesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	endpoints, err := armcdn.NewEndpointsClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	afdEndpoints, err := armcdn.NewAFDEndpointsClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	routes, err := armcdn.NewRoutesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}

	var result []Entrypoint
	pager := profiles.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, profile := range page.Value {
			id := internal.Deref(profile.ID)
			if !s.Target.InScope(id) || profile.SKU == nil || profile.SKU.Name == nil {
				continue
			}
			rg, name := internal.ResourceGroupOf(id), internal.Deref(profile.Name)

			if *profile.SKU.Name == armcdn.SKUNameStandardAzureFrontDoor || *profile.SKU.Name == armcdn.SKUNamePremiumAzureFrontDoor {
				epPager := afdEndpoints.NewListByProfilePager(rg, name, nil)
				for epPager.More() {
					epPage, err := epPager.NextPage(ctx)
					if err != nil {
						return nil, err
					}
					for _, ep := range epPage.Value {
						epName := internal.Deref(ep.Name)
						rPager := routes.NewListByEndpointPager(rg, name, epName, nil)
						for rPager.More() {
							rPage, err := rPager.NextPage(ctx)
							if err != nil {
								return nil, err
							}
							for _, r := range rPage.Value {
								e := Entrypoint{ID: internal.Deref(r.ID), Name: name + "/" + epName + "/" + internal.Deref(r.Name)}
								if p := r.Properties; p != nil {
									redirect := p.HTTPSRedirect != nil && *p.HTTPSRedirect == armcdn.HTTPSRedirectEnabled
									httpServed := false
									for _, proto := range p.SupportedProtocols {
										if proto != nil && *proto == armcdn.AFDEndpointProtocolsHTTP {
											httpServed = true
										}
									}
									e.HTTPSOnly = redirect || !httpServed
								}
								result = append(result, e)
							}
						}
					}
				}
				continue
			}

			epPager := endpoints.NewListByProfilePager(rg, name, nil)
			for epPager.More() {
				epPage, err := epPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, ep := range epPage.Value {
					e := Entrypoint{ID: internal.Deref(ep.ID), Name: name + "/" + internal.Deref(ep.Name)}
					if ep.Properties != nil {
						e.HTTPSOnly = ep.Properties.IsHTTPAllowed != nil && !*ep.Properties.IsHTTPAllowed
					}
					result = append(result, e)
				}
			}
		}
	}
	return result, nil
}
