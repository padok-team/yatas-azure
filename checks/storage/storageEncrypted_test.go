package storage

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func run(t *testing.T, in internal.Fetched[Account], want string) {
	t.Helper()
	check := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfEncrypted(cfg, in, EncryptedID) })
	if check.Status != want {
		t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
	}
	if check.Categories[len(check.Categories)-1] != "HDS" {
		t.Errorf("not tagged HDS: %v", check.Categories)
	}
}

func Test_checkIfEncrypted(t *testing.T) {
	ok := func(a Account) internal.Fetched[Account] { return internal.Fetched[Account]{Items: []Account{a}} }
	run(t, ok(Account{Name: "a", ServicesEncrypted: true, CustomerManagedKey: true}), "OK")
	run(t, ok(Account{Name: "a", ServicesEncrypted: true, InfrastructureEncryption: true}), "OK")
	run(t, ok(Account{Name: "a", ServicesEncrypted: true}), "FAIL")
	run(t, ok(Account{Name: "a", CustomerManagedKey: true}), "FAIL")
	run(t, internal.Fetched[Account]{Err: errors.New("403")}, "FAIL")
}
