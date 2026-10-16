package defender

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func runPlans(t *testing.T, in internal.Fetched[Plan], want string) {
	t.Helper()
	check := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfThreatProtectionEnabled(cfg, in, "test") })
	if check.Status != want {
		t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
	}
	if check.Categories[len(check.Categories)-1] != "HDS" {
		t.Errorf("not tagged HDS: %v", check.Categories)
	}
}

func plans(p ...Plan) internal.Fetched[Plan] { return internal.Fetched[Plan]{Items: p} }

func Test_checkIfThreatProtectionEnabled(t *testing.T) {
	runPlans(t, plans(Plan{"Arm", true}, Plan{"StorageAccounts", true}), "OK")
	// CSPM only is posture management, not threat detection.
	runPlans(t, plans(Plan{"Arm", true}, Plan{"CloudPosture", true}), "FAIL")
	runPlans(t, plans(Plan{"StorageAccounts", true}), "FAIL")
	runPlans(t, plans(Plan{"Arm", false}, Plan{"StorageAccounts", false}), "FAIL")
	runPlans(t, internal.Fetched[Plan]{Err: errors.New("403")}, "FAIL")
}

func Test_checkIfPolicyEnabled(t *testing.T) {
	run := func(in internal.Fetched[PolicyAssignment], want string) {
		t.Helper()
		check := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfPolicyEnabled(cfg, in, "test") })
		if check.Status != want {
			t.Errorf("status = %s, want %s", check.Status, want)
		}
	}
	run(internal.Fetched[PolicyAssignment]{Items: []PolicyAssignment{{ID: "a"}}}, "OK")
	run(internal.Fetched[PolicyAssignment]{}, "FAIL")
	run(internal.Fetched[PolicyAssignment]{Err: errors.New("403")}, "FAIL")
}
