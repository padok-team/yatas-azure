package sql

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/padok-team/yatas-azure/internal"
)

// enrich fills the lock and auditing posture of every server.
func enrich(s internal.Session, servers []Server) error {
	if len(servers) == 0 {
		return nil
	}
	ctx := context.TODO()
	locks, err := armlocks.NewManagementLocksClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return err
	}
	auditing, err := armsql.NewServerBlobAuditingPoliciesClient(s.Target.SubscriptionID, s.Credential, nil)
	if err != nil {
		return err
	}
	for i := range servers {
		srv := &servers[i]
		pager := locks.NewListByScopePager(srv.ID, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			if len(page.Value) > 0 {
				srv.DeleteLock = true
			}
		}
		if srv.Kind == KindSQL {
			res, err := auditing.Get(ctx, internal.ResourceGroupOf(srv.ID), srv.Name, nil)
			if err != nil {
				return err
			}
			p := res.Properties
			srv.Auditing = p != nil && p.State != nil && *p.State == armsql.BlobAuditingPolicyStateEnabled
			continue
		}
		diag, err := internal.GetDiagnosticSettings(s, srv.ID)
		if err != nil {
			return err
		}
		srv.Auditing = internal.LogsShipped(diag)
	}
	return nil
}
