package sql

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

type checkFn func(commons.CheckConfig, internal.Fetched[Server], string)

func run(t *testing.T, fn checkFn, in internal.Fetched[Server], want string) {
	t.Helper()
	check := internal.RunCheck(func(cfg commons.CheckConfig) { fn(cfg, in, "test") })
	if check.Status != want {
		t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
	}
	if check.Categories[len(check.Categories)-1] != "HDS" {
		t.Errorf("not tagged HDS: %v", check.Categories)
	}
}

func one(s Server) internal.Fetched[Server] { return internal.Fetched[Server]{Items: []Server{s}} }

func Test_checkIfNotPublic(t *testing.T) {
	run(t, checkIfNotPublic, one(Server{Name: "s", Kind: KindSQL}), "OK")
	run(t, checkIfNotPublic, one(Server{Name: "s", Kind: KindSQL, PublicAccess: true}), "FAIL")
}

func Test_checkIfEncrypted(t *testing.T) {
	run(t, checkIfEncrypted, one(Server{Name: "s", Kind: KindSQL, Databases: []Database{{Name: "d", TDEEnabled: true}}}), "OK")
	run(t, checkIfEncrypted, one(Server{Name: "s", Kind: KindPostgreSQL}), "OK")
	run(t, checkIfEncrypted, one(Server{Name: "s", Kind: KindSQL, Databases: []Database{{Name: "d", TDEEnabled: false}}}), "FAIL")
}

func Test_checkIfBackupWithPITR(t *testing.T) {
	run(t, checkIfBackupWithPITR, one(Server{Name: "s", Kind: KindSQL, Databases: []Database{{Name: "d", PITRRetentionDays: 14}}}), "OK")
	run(t, checkIfBackupWithPITR, one(Server{Name: "s", Kind: KindMySQL, BackupRetentionDays: 7}), "OK")
	run(t, checkIfBackupWithPITR, one(Server{Name: "s", Kind: KindSQL, Databases: []Database{{Name: "d", PITRRetentionDays: 1}}}), "FAIL")
	run(t, checkIfBackupWithPITR, one(Server{Name: "s", Kind: KindPostgreSQL, BackupRetentionDays: 3}), "FAIL")
}

func Test_checkIfFirewallRestricted(t *testing.T) {
	run(t, checkIfFirewallRestricted, one(Server{Name: "s", FirewallRules: []FirewallRule{{Name: "office", Start: "10.0.0.1", End: "10.0.0.9"}}}), "OK")
	run(t, checkIfFirewallRestricted, one(Server{Name: "s", FirewallRules: []FirewallRule{{Name: "all", Start: "0.0.0.0", End: "255.255.255.255"}}}), "FAIL")
	run(t, checkIfFirewallRestricted, one(Server{Name: "s", FirewallRules: []FirewallRule{{Name: "AllowAllWindowsAzureIps", Start: "0.0.0.0", End: "0.0.0.0"}}}), "FAIL")
}

func Test_checkIfMinorVersionAutoUpdated(t *testing.T) {
	run(t, checkIfMinorVersionAutoUpdated, one(Server{Name: "s", Kind: KindSQL, AutoMinorUpgrade: true}), "OK")
	run(t, checkIfMinorVersionAutoUpdated, one(Server{Name: "s", Kind: KindPostgreSQL}), "FAIL")
}

// A fetch error must never be reported as compliant.
func Test_fetchErrorFails(t *testing.T) {
	failed := internal.Fetched[Server]{Err: errors.New("403 forbidden")}
	for _, fn := range []checkFn{checkIfNotPublic, checkIfEncrypted, checkIfBackupWithPITR, checkIfFirewallRestricted, checkIfMinorVersionAutoUpdated} {
		run(t, fn, failed, "FAIL")
	}
}
