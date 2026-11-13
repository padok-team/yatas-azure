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

func statusOf(fn func(commons.CheckConfig, internal.Fetched[Account], string), a Account) string {
	in := internal.Fetched[Account]{Items: []Account{a}}
	return internal.RunCheck(func(cfg commons.CheckConfig) { fn(cfg, in, "test") }).Status
}

func Test_phase2Checks(t *testing.T) {
	cases := []struct {
		name string
		fn   func(commons.CheckConfig, internal.Fetched[Account], string)
		ok   Account
		ko   Account
	}{
		{"softdelete", checkIfSoftDelete, Account{BlobProps: true, SoftDelete: true}, Account{BlobProps: true}},
		{"geo", checkIfGeoReplicated, Account{SKU: "Standard_RAGRS"}, Account{SKU: "Standard_LRS"}},
		{"lifecycle", checkIfLifecyclePolicy, Account{BlobProps: true, LifecyclePolicy: true}, Account{BlobProps: true}},
		{"immutability", checkIfImmutability, Account{BlobProps: true, Immutability: true}, Account{BlobProps: true}},
		{"public", checkIfNoPublicAccess, Account{}, Account{PublicBlobAccess: true}},
		{"transport", checkIfSecureTransport, Account{HTTPSOnly: true, MinTLS12: true}, Account{HTTPSOnly: true}},
	}
	for _, c := range cases {
		if got := statusOf(c.fn, c.ok); got != "OK" {
			t.Errorf("%s ok case = %s", c.name, got)
		}
		if got := statusOf(c.fn, c.ko); got != "FAIL" {
			t.Errorf("%s ko case = %s", c.name, got)
		}
	}
	if got := statusOf(checkIfSoftDelete, Account{}); got != "OK" {
		t.Errorf("accounts without blob service must be skipped, got %s", got)
	}
}
