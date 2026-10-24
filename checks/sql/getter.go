package sql

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/padok-team/yatas-azure/internal"
)

// Kinds of database servers covered by the category.
const (
	KindSQL        = "Azure SQL"
	KindPostgreSQL = "PostgreSQL flexible server"
	KindMySQL      = "MySQL flexible server"
)

// FirewallRule is an IPv4 range allowed through the server firewall.
type FirewallRule struct {
	Name  string
	Start string
	End   string
}

// Database is an Azure SQL database (flexible servers are evaluated as a whole).
type Database struct {
	ID                string
	Name              string
	TDEEnabled        bool
	PITRRetentionDays int32
}

// Server is a managed database server of any kind, normalised so the checks do
// not care whether it is Azure SQL, PostgreSQL or MySQL.
type Server struct {
	ID   string
	Name string
	Kind string
	// PublicAccess is true when the server is reachable through a public endpoint.
	PublicAccess  bool
	FirewallRules []FirewallRule
	// Databases is only filled for Azure SQL. Flexible servers are always
	// encrypted at rest and back up the whole server.
	Databases []Database
	// BackupRetentionDays is the server-level PITR retention (flexible servers).
	BackupRetentionDays int32
	// AutoMinorUpgrade: Azure SQL is patched by the platform; flexible servers
	// are patched automatically, in a custom maintenance window when defined.
	AutoMinorUpgrade bool
}

// MinPITRDays is the minimum PITR retention accepted by the backup check.
const MinPITRDays = 7

// GetServers lists every database server of the target.
func GetServers(s internal.Session) ([]Server, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	var servers []Server
	for _, fetch := range []func(internal.Session) ([]Server, error){getSQLServers, getPostgreSQLServers, getMySQLServers} {
		list, err := fetch(s)
		if err != nil {
			return nil, err
		}
		servers = append(servers, list...)
	}
	return servers, nil
}

func getSQLServers(s internal.Session) ([]Server, error) {
	ctx := context.TODO()
	sub := s.Target.SubscriptionID
	servers, err := armsql.NewServersClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	fw, err := armsql.NewFirewallRulesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	dbs, err := armsql.NewDatabasesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	tde, err := armsql.NewTransparentDataEncryptionsClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	pitr, err := armsql.NewBackupShortTermRetentionPoliciesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}

	var result []Server
	pager := servers.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			id := internal.Deref(raw.ID)
			if !s.Target.InScope(id) {
				continue
			}
			name, rg := internal.Deref(raw.Name), internal.ResourceGroupOf(id)
			srv := Server{ID: id, Name: name, Kind: KindSQL, AutoMinorUpgrade: true, PublicAccess: true}
			if raw.Properties != nil && raw.Properties.PublicNetworkAccess != nil {
				srv.PublicAccess = *raw.Properties.PublicNetworkAccess == armsql.ServerNetworkAccessFlagEnabled
			}

			fwPager := fw.NewListByServerPager(rg, name, nil)
			for fwPager.More() {
				fwPage, err := fwPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, r := range fwPage.Value {
					if r.Properties != nil {
						srv.FirewallRules = append(srv.FirewallRules, FirewallRule{Name: internal.Deref(r.Name), Start: internal.Deref(r.Properties.StartIPAddress), End: internal.Deref(r.Properties.EndIPAddress)})
					}
				}
			}

			dbPager := dbs.NewListByServerPager(rg, name, nil)
			for dbPager.More() {
				dbPage, err := dbPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, d := range dbPage.Value {
					dbName := internal.Deref(d.Name)
					if dbName == "master" {
						continue
					}
					db := Database{ID: internal.Deref(d.ID), Name: dbName}
					t, err := tde.Get(ctx, rg, name, dbName, armsql.TransparentDataEncryptionNameCurrent, nil)
					if err != nil {
						return nil, err
					}
					db.TDEEnabled = t.Properties != nil && t.Properties.State != nil && *t.Properties.State == armsql.TransparentDataEncryptionStateEnabled
					p, err := pitr.Get(ctx, rg, name, dbName, armsql.ShortTermRetentionPolicyNameDefault, nil)
					if err != nil {
						return nil, err
					}
					if p.Properties != nil {
						db.PITRRetentionDays = internal.Deref(p.Properties.RetentionDays)
					}
					srv.Databases = append(srv.Databases, db)
				}
			}
			result = append(result, srv)
		}
	}
	return result, nil
}

func getPostgreSQLServers(s internal.Session) ([]Server, error) {
	ctx := context.TODO()
	sub := s.Target.SubscriptionID
	servers, err := armpostgresqlflexibleservers.NewServersClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	fw, err := armpostgresqlflexibleservers.NewFirewallRulesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var result []Server
	pager := servers.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			id := internal.Deref(raw.ID)
			if !s.Target.InScope(id) {
				continue
			}
			name := internal.Deref(raw.Name)
			srv := Server{ID: id, Name: name, Kind: KindPostgreSQL, PublicAccess: true}
			if p := raw.Properties; p != nil {
				if p.Network != nil {
					private := internal.Deref(p.Network.DelegatedSubnetResourceID) != ""
					disabled := p.Network.PublicNetworkAccess != nil && *p.Network.PublicNetworkAccess == armpostgresqlflexibleservers.ServerPublicNetworkAccessStateDisabled
					srv.PublicAccess = !private && !disabled
				}
				if p.Backup != nil {
					srv.BackupRetentionDays = internal.Deref(p.Backup.BackupRetentionDays)
				}
				srv.AutoMinorUpgrade = p.MaintenanceWindow != nil && internal.Deref(p.MaintenanceWindow.CustomWindow) == "Enabled"
			}
			fwPager := fw.NewListByServerPager(internal.ResourceGroupOf(id), name, nil)
			for fwPager.More() {
				fwPage, err := fwPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, r := range fwPage.Value {
					if r.Properties != nil {
						srv.FirewallRules = append(srv.FirewallRules, FirewallRule{Name: internal.Deref(r.Name), Start: internal.Deref(r.Properties.StartIPAddress), End: internal.Deref(r.Properties.EndIPAddress)})
					}
				}
			}
			result = append(result, srv)
		}
	}
	return result, nil
}

func getMySQLServers(s internal.Session) ([]Server, error) {
	ctx := context.TODO()
	sub := s.Target.SubscriptionID
	servers, err := armmysqlflexibleservers.NewServersClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	fw, err := armmysqlflexibleservers.NewFirewallRulesClient(sub, s.Credential, nil)
	if err != nil {
		return nil, err
	}
	var result []Server
	pager := servers.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, raw := range page.Value {
			id := internal.Deref(raw.ID)
			if !s.Target.InScope(id) {
				continue
			}
			name := internal.Deref(raw.Name)
			srv := Server{ID: id, Name: name, Kind: KindMySQL, PublicAccess: true}
			if p := raw.Properties; p != nil {
				if p.Network != nil {
					private := internal.Deref(p.Network.DelegatedSubnetResourceID) != ""
					disabled := p.Network.PublicNetworkAccess != nil && *p.Network.PublicNetworkAccess == armmysqlflexibleservers.EnableStatusEnumDisabled
					srv.PublicAccess = !private && !disabled
				}
				if p.Backup != nil {
					srv.BackupRetentionDays = internal.Deref(p.Backup.BackupRetentionDays)
				}
				srv.AutoMinorUpgrade = p.MaintenanceWindow != nil && internal.Deref(p.MaintenanceWindow.CustomWindow) == "Enabled"
			}
			fwPager := fw.NewListByServerPager(internal.ResourceGroupOf(id), name, nil)
			for fwPager.More() {
				fwPage, err := fwPager.NextPage(ctx)
				if err != nil {
					return nil, err
				}
				for _, r := range fwPage.Value {
					if r.Properties != nil {
						srv.FirewallRules = append(srv.FirewallRules, FirewallRule{Name: internal.Deref(r.Name), Start: internal.Deref(r.Properties.StartIPAddress), End: internal.Deref(r.Properties.EndIPAddress)})
					}
				}
			}
			result = append(result, srv)
		}
	}
	return result, nil
}
