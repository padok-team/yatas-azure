package backup

import (
	"errors"
	"testing"
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_checkIfRecoveryPointLessThan24h(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	run := func(in internal.Fetched[ProtectedVM], want string) {
		t.Helper()
		check := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfRecoveryPointLessThan24h(cfg, in, "test", clock) })
		if check.Status != want {
			t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
		}
		if check.Categories[len(check.Categories)-1] != "HDS" {
			t.Errorf("not tagged HDS: %v", check.Categories)
		}
	}
	vm := func(last time.Time) internal.Fetched[ProtectedVM] {
		return internal.Fetched[ProtectedVM]{Items: []ProtectedVM{{Name: "vm", LastRecoveryPoint: last}}}
	}
	run(vm(now.Add(-2*time.Hour)), "OK")
	run(vm(now.Add(-30*time.Hour)), "FAIL")
	run(vm(time.Time{}), "FAIL")
	run(internal.Fetched[ProtectedVM]{Err: errors.New("403")}, "FAIL")
}
