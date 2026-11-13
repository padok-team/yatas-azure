package sql

import (
	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	LockID     = "AZURE_SQL_006"
	AuditingID = "AZURE_SQL_007"
)

// checkIfDeleteLock (≈ AWS "RDS have delete protection"): Azure databases have no
// delete-protection flag, a resource lock plays that role.
func checkIfDeleteLock(cfg commons.CheckConfig, in internal.Fetched[Server], id string) {
	check := internal.NewCheck("Database servers are protected against accidental deletion", "Check that a management lock (CanNotDelete or ReadOnly) applies to database servers", id, "Reliability", "Good Practice")
	internal.Evaluate(cfg, check, in, "database servers", func(s Server) *internal.Verdict {
		if s.DeleteLock {
			return internal.Yes(s.ID, s.Kind+" "+s.Name+" is protected by a resource lock")
		}
		return internal.No(s.ID, s.Kind+" "+s.Name+" has no resource lock")
	})
}

// checkIfAuditing (≈ AWS "RDS logs are exported").
func checkIfAuditing(cfg commons.CheckConfig, in internal.Fetched[Server], id string) {
	check := internal.NewCheck("Database servers have auditing enabled", "Check that audit logs of database servers are enabled and exported", id)
	internal.Evaluate(cfg, check, in, "database servers", func(s Server) *internal.Verdict {
		if s.Auditing {
			return internal.Yes(s.ID, "Auditing is enabled on "+s.Kind+" "+s.Name)
		}
		return internal.No(s.ID, "Auditing is not enabled on "+s.Kind+" "+s.Name)
	})
}
