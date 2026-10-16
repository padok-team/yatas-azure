package defender

import (
	"fmt"
	"sort"
	"strings"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
const (
	ThreatProtectionID = "AZURE_DEF_001"
	PolicyID           = "AZURE_DEF_002"
)

// ControlPlanePlan is the Defender plan watching Azure Resource Manager
// operations (the Azure analogue of GuardDuty's CloudTrail/management-event
// analysis). It applies to every subscription, whatever it hosts.
const ControlPlanePlan = "Arm"

// WorkloadPlans are the Defender for Cloud workload-protection (CWP) plans that
// produce threat detections for a resource type. CSPM plans (CloudPosture,
// Foundational CSPM) only assess posture and do not count as threat detection.
var WorkloadPlans = map[string]bool{
	"VirtualMachines":               true, // Defender for Servers
	"SqlServers":                    true, // Defender for Azure SQL
	"SqlServerVirtualMachines":      true, // Defender for SQL on machines
	"OpenSourceRelationalDatabases": true, // Defender for PostgreSQL/MySQL/MariaDB
	"CosmosDbs":                     true,
	"StorageAccounts":               true,
	"AppServices":                   true,
	"Containers":                    true, // Defender for Containers (AKS, ACR)
	"KeyVaults":                     true,
}

// checkIfThreatProtectionEnabled (≈ AWS "GuardDuty is enabled in the account").
// GuardDuty is threat detection, so the Azure equivalent is Defender for Cloud's
// workload-protection plans: the subscription must have the control-plane plan
// (Arm) and at least one workload plan on the Standard tier.
func checkIfThreatProtectionEnabled(checkConfig commons.CheckConfig, plans internal.Fetched[Plan], testName string) {
	check := internal.NewHDSCheck("Microsoft Defender for Cloud threat protection is enabled in the subscription", "Check that Defender for Cloud threat-detection plans (Resource Manager + at least one workload plan) are on the Standard tier", testName)
	if plans.Failed(&check, "Defender for Cloud plans") {
		checkConfig.Queue <- check
		return
	}
	armOn := false
	var workloads []string
	for _, p := range plans.Items {
		if !p.Standard {
			continue
		}
		if p.Name == ControlPlanePlan {
			armOn = true
		}
		if WorkloadPlans[p.Name] {
			workloads = append(workloads, p.Name)
		}
	}
	sort.Strings(workloads)
	switch {
	case !armOn:
		internal.Fail(&check, "", "Defender for Resource Manager ("+ControlPlanePlan+") is not enabled")
	case len(workloads) == 0:
		internal.Fail(&check, "", "No Defender for Cloud workload protection plan is enabled")
	default:
		internal.Pass(&check, "", "Defender for Cloud threat protection is enabled (Resource Manager + "+strings.Join(workloads, ", ")+")")
	}
	checkConfig.Queue <- check
}

// checkIfPolicyEnabled (≈ AWS "AWS Config is enabled in the account"). Azure
// Policy continuously evaluates resource configuration against assigned rules;
// an assignment (e.g. the Microsoft cloud security benchmark that Defender for
// Cloud assigns) must apply to the subscription.
func checkIfPolicyEnabled(checkConfig commons.CheckConfig, assignments internal.Fetched[PolicyAssignment], testName string) {
	check := internal.NewHDSCheck("Azure Policy is enabled in the subscription", "Check that at least one Azure Policy assignment evaluates the configuration compliance of the subscription", testName)
	if assignments.Failed(&check, "Azure Policy assignments") {
		checkConfig.Queue <- check
		return
	}
	if len(assignments.Items) == 0 {
		internal.Fail(&check, "", "No Azure Policy assignment applies to the subscription")
	} else {
		internal.Pass(&check, "", fmt.Sprintf("%d Azure Policy assignment(s) apply to the subscription", len(assignments.Items)))
	}
	checkConfig.Queue <- check
}
