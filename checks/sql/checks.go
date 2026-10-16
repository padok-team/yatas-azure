package sql

import (
	"fmt"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	PrivateID     = "AZURE_SQL_001"
	EncryptedID   = "AZURE_SQL_002"
	BackupID      = "AZURE_SQL_003"
	FirewallID    = "AZURE_SQL_004"
	AutoUpgradeID = "AZURE_SQL_005"
)

// AZURE_SQL_001 (≈ AWS "RDS aren't publicly accessible").
func checkIfNotPublic(checkConfig commons.CheckConfig, servers internal.Fetched[Server], testName string) {
	check := internal.NewHDSCheck("Database servers aren't publicly accessible", "Check that Azure SQL, PostgreSQL and MySQL servers deny public network access", testName)
	if servers.Failed(&check, "database servers") {
		checkConfig.Queue <- check
		return
	}
	for _, s := range servers.Items {
		if s.PublicAccess {
			internal.Fail(&check, s.ID, fmt.Sprintf("%s %s allows public network access", s.Kind, s.Name))
		} else {
			internal.Pass(&check, s.ID, fmt.Sprintf("%s %s denies public network access", s.Kind, s.Name))
		}
	}
	checkConfig.Queue <- check
}

// AZURE_SQL_002 (≈ AWS "RDS are encrypted"): TDE on every Azure SQL database.
// Flexible servers are always encrypted at rest (AES-256), so they pass.
func checkIfEncrypted(checkConfig commons.CheckConfig, servers internal.Fetched[Server], testName string) {
	check := internal.NewHDSCheck("Databases are encrypted", "Check that Transparent Data Encryption is enabled on Azure SQL databases (flexible servers are always encrypted at rest)", testName)
	if servers.Failed(&check, "database servers") {
		checkConfig.Queue <- check
		return
	}
	for _, s := range servers.Items {
		if s.Kind != KindSQL {
			internal.Pass(&check, s.ID, fmt.Sprintf("%s %s is always encrypted at rest", s.Kind, s.Name))
			continue
		}
		for _, db := range s.Databases {
			if db.TDEEnabled {
				internal.Pass(&check, db.ID, "Transparent Data Encryption is enabled on database "+s.Name+"/"+db.Name)
			} else {
				internal.Fail(&check, db.ID, "Transparent Data Encryption is not enabled on database "+s.Name+"/"+db.Name)
			}
		}
	}
	checkConfig.Queue <- check
}

// AZURE_SQL_003 (≈ AWS "RDS are backedup automatically with PITR").
func checkIfBackupWithPITR(checkConfig commons.CheckConfig, servers internal.Fetched[Server], testName string) {
	check := internal.NewHDSCheck("Databases are backed up automatically with PITR", fmt.Sprintf("Check that automated backups with point-in-time restore are retained at least %d days", MinPITRDays), testName)
	if servers.Failed(&check, "database servers") {
		checkConfig.Queue <- check
		return
	}
	evaluate := func(id, label string, days int32) {
		if days >= MinPITRDays {
			internal.Pass(&check, id, fmt.Sprintf("%s has PITR retention of %d days", label, days))
		} else {
			internal.Fail(&check, id, fmt.Sprintf("%s has PITR retention of %d days, at least %d required", label, days, MinPITRDays))
		}
	}
	for _, s := range servers.Items {
		if s.Kind == KindSQL {
			for _, db := range s.Databases {
				evaluate(db.ID, "Database "+s.Name+"/"+db.Name, db.PITRRetentionDays)
			}
			continue
		}
		evaluate(s.ID, s.Kind+" "+s.Name, s.BackupRetentionDays)
	}
	checkConfig.Queue <- check
}

// AZURE_SQL_004 (≈ AWS "RDS have properly restricted security groups"): no
// firewall rule opens the server to the whole Internet or to every Azure service.
func checkIfFirewallRestricted(checkConfig commons.CheckConfig, servers internal.Fetched[Server], testName string) {
	check := internal.NewHDSCheck("Database servers have properly restricted firewall rules", "Check that no firewall rule allows 0.0.0.0-255.255.255.255 or all Azure services (0.0.0.0)", testName)
	if servers.Failed(&check, "database servers") {
		checkConfig.Queue <- check
		return
	}
	for _, s := range servers.Items {
		failed := false
		for _, r := range s.FirewallRules {
			switch {
			case r.Start == "0.0.0.0" && r.End == "255.255.255.255":
				internal.Fail(&check, s.ID, fmt.Sprintf("%s %s firewall rule %s allows the whole Internet", s.Kind, s.Name, r.Name))
				failed = true
			case r.Start == "0.0.0.0" && r.End == "0.0.0.0":
				internal.Fail(&check, s.ID, fmt.Sprintf("%s %s firewall rule %s allows all Azure services", s.Kind, s.Name, r.Name))
				failed = true
			}
		}
		if !failed {
			internal.Pass(&check, s.ID, fmt.Sprintf("%s %s has properly restricted firewall rules", s.Kind, s.Name))
		}
	}
	checkConfig.Queue <- check
}

// AZURE_SQL_005 (≈ AWS "RDS have minor versions automatically updated"). Azure
// SQL is patched by the platform. PostgreSQL/MySQL flexible servers always
// receive minor updates, so the check asks for a custom maintenance window to
// make the update schedule controlled and auditable.
func checkIfMinorVersionAutoUpdated(checkConfig commons.CheckConfig, servers internal.Fetched[Server], testName string) {
	check := internal.NewHDSCheck("Database servers have minor versions automatically updated", "Check that Azure SQL is platform-patched and that flexible servers define a custom maintenance window for automatic minor updates", testName)
	if servers.Failed(&check, "database servers") {
		checkConfig.Queue <- check
		return
	}
	for _, s := range servers.Items {
		if s.AutoMinorUpgrade {
			internal.Pass(&check, s.ID, fmt.Sprintf("%s %s minor versions are updated automatically", s.Kind, s.Name))
		} else {
			internal.Fail(&check, s.ID, fmt.Sprintf("%s %s has no custom maintenance window for automatic minor updates", s.Kind, s.Name))
		}
	}
	checkConfig.Queue <- check
}
