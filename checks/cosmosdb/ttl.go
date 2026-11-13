package cosmosdb

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// TTLID is the check's unique, stable ID.
const TTLID = "AZURE_COS_003"

// Container is a Cosmos DB (NoSQL API) container.
type Container struct {
	ID   string
	Name string // <account>/<database>/<container>
	TTL  bool   // a default time to live is configured
}

// GetContainers lists the containers of every NoSQL-API Cosmos DB account. Other
// APIs (Mongo, Cassandra, Table, Gremlin) answer 400/404 and are skipped.
func GetContainers(s internal.Session) ([]Container, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	accounts, err := GetAccounts(s)
	if err != nil {
		return nil, err
	}
	client, err := armcosmos.NewSQLResourcesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	ctx := context.TODO()
	var containers []Container
	for _, a := range accounts {
		rg := internal.ResourceGroupOf(a.ID)
		dbs := client.NewListSQLDatabasesPager(rg, a.Name, nil)
		for dbs.More() {
			dbPage, err := dbs.NextPage(ctx)
			if err != nil {
				if unsupportedAPI(err) {
					break
				}
				return nil, err
			}
			for _, db := range dbPage.Value {
				dbName := internal.Deref(db.Name)
				cs := client.NewListSQLContainersPager(rg, a.Name, dbName, nil)
				for cs.More() {
					cPage, err := cs.NextPage(ctx)
					if err != nil {
						return nil, err
					}
					for _, c := range cPage.Value {
						ct := Container{ID: internal.Deref(c.ID), Name: a.Name + "/" + dbName + "/" + internal.Deref(c.Name)}
						if c.Properties != nil && c.Properties.Resource != nil {
							ct.TTL = c.Properties.Resource.DefaultTTL != nil
						}
						containers = append(containers, ct)
					}
				}
			}
		}
	}
	return containers, nil
}

func unsupportedAPI(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && (respErr.StatusCode == http.StatusBadRequest || respErr.StatusCode == http.StatusNotFound)
}

// checkIfTTL (≈ AWS "Dynamodb have TTL configured").
func checkIfTTL(cfg commons.CheckConfig, in internal.Fetched[Container], id string) {
	check := internal.NewCheck("Cosmos DB containers have a time to live configured", "Check that Cosmos DB containers define a default time to live", id, "Cost", "Good Practice")
	internal.Evaluate(cfg, check, in, "Cosmos DB containers", func(c Container) *internal.Verdict {
		if c.TTL {
			return internal.Yes(c.ID, "Container "+c.Name+" has a time to live configured")
		}
		return internal.No(c.ID, "Container "+c.Name+" has no time to live configured")
	})
}
