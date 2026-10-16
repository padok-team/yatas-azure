package disks

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func fetched(d ...Disk) internal.Fetched[Disk] { return internal.Fetched[Disk]{Items: d} }

func run(t *testing.T, fn func(commons.CheckConfig, internal.Fetched[Disk], string), in internal.Fetched[Disk], want string) {
	t.Helper()
	check := internal.RunCheck(func(cfg commons.CheckConfig) { fn(cfg, in, "test") })
	if check.Status != want {
		t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
	}
	if check.Categories[len(check.Categories)-1] != "HDS" {
		t.Errorf("not tagged HDS: %v", check.Categories)
	}
}

func Test_checkIfDisksEncrypted(t *testing.T) {
	run(t, checkIfDisksEncrypted, fetched(Disk{Name: "d", EncryptionType: "EncryptionAtRestWithCustomerKey"}), "OK")
	run(t, checkIfDisksEncrypted, fetched(Disk{Name: "d", EncryptionType: "EncryptionAtRestWithPlatformAndCustomerKeys"}), "OK")
	run(t, checkIfDisksEncrypted, fetched(Disk{Name: "d", EncryptionType: "EncryptionAtRestWithPlatformKey"}), "FAIL")
	run(t, checkIfDisksEncrypted, fetched(Disk{Name: "d"}), "FAIL")
	run(t, checkIfDisksEncrypted, internal.Fetched[Disk]{Err: errors.New("403")}, "FAIL")
}

func Test_checkIfSnapshotsEncrypted(t *testing.T) {
	run(t, checkIfSnapshotsEncrypted, fetched(Disk{Name: "s", Snapshot: true, EncryptionType: "EncryptionAtRestWithCustomerKey"}), "OK")
	run(t, checkIfSnapshotsEncrypted, fetched(Disk{Name: "s", Snapshot: true, EncryptionType: "EncryptionAtRestWithPlatformKey"}), "FAIL")
	run(t, checkIfSnapshotsEncrypted, internal.Fetched[Disk]{Err: errors.New("403")}, "FAIL")
}
