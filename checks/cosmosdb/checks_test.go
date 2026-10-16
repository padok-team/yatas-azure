package cosmosdb

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

type checkFn func(commons.CheckConfig, internal.Fetched[Account], string)

func run(t *testing.T, fn checkFn, in internal.Fetched[Account], want string) {
	t.Helper()
	check := internal.RunCheck(func(cfg commons.CheckConfig) { fn(cfg, in, "test") })
	if check.Status != want {
		t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
	}
	if check.Categories[len(check.Categories)-1] != "HDS" {
		t.Errorf("not tagged HDS: %v", check.Categories)
	}
}

func one(a Account) internal.Fetched[Account] { return internal.Fetched[Account]{Items: []Account{a}} }

func Test_checkIfEncrypted(t *testing.T) {
	run(t, checkIfEncrypted, one(Account{Name: "a", CustomerManagedKey: true}), "OK")
	run(t, checkIfEncrypted, one(Account{Name: "a"}), "FAIL")
}

func Test_checkIfContinuousBackup(t *testing.T) {
	run(t, checkIfContinuousBackup, one(Account{Name: "a", ContinuousBackup: true}), "OK")
	run(t, checkIfContinuousBackup, one(Account{Name: "a"}), "FAIL")
}

func Test_fetchErrorFails(t *testing.T) {
	for _, fn := range []checkFn{checkIfEncrypted, checkIfContinuousBackup} {
		run(t, fn, internal.Fetched[Account]{Err: errors.New("403")}, "FAIL")
	}
}
