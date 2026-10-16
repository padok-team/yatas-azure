package rbac

import (
	"strings"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// ElevateRightsID is the check's unique, stable ID.
const ElevateRightsID = "AZURE_RBAC_001"

// checkIfCannotElevateRights (≈ AWS "IAM User can't elevate rights"): no identity
// holds, at subscription scope or above, a role (built-in or custom) that grants
// Microsoft.Authorization/roleAssignments/write. Assignments carrying an ABAC
// condition (constrained delegation) are not counted.
func checkIfCannotElevateRights(checkConfig commons.CheckConfig, principals internal.Fetched[Principal], testName string) {
	check := internal.NewHDSCheck("RBAC identities can't elevate rights", "Check that no identity can grant role assignments (Microsoft.Authorization/roleAssignments/write) at subscription scope or above", testName)
	if principals.Failed(&check, "role assignments") {
		checkConfig.Queue <- check
		return
	}
	for _, p := range principals.Items {
		label := p.Type + " " + p.ID
		if len(p.ElevatingRoles) > 0 {
			internal.Fail(&check, p.ID, label+" can elevate rights through "+strings.Join(p.ElevatingRoles, ", "))
		} else if len(p.ConstrainedRoles) > 0 {
			internal.Pass(&check, p.ID, label+" can only delegate roles under an ABAC condition ("+strings.Join(p.ConstrainedRoles, ", ")+")")
		} else {
			internal.Pass(&check, p.ID, label+" cannot elevate rights")
		}
	}
	checkConfig.Queue <- check
}
