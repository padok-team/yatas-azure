package disks

import (
	"errors"
	"testing"
	"time"

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

func statusOf(fn func(commons.CheckConfig, string)) string {
	return internal.RunCheck(func(cfg commons.CheckConfig) { fn(cfg, "test") }).Status
}

func Test_phase2Checks(t *testing.T) {
	one := func(d Disk) internal.Fetched[Disk] { return internal.Fetched[Disk]{Items: []Disk{d}} }
	run := func(in internal.Fetched[Disk]) func(commons.CheckConfig, string) {
		return func(cfg commons.CheckConfig, id string) { checkIfDisksInUse(cfg, in, id) }
	}
	if statusOf(run(one(Disk{Attached: true}))) != "OK" || statusOf(run(one(Disk{}))) != "FAIL" {
		t.Error("in-use check")
	}
	sku := func(s string) string {
		return statusOf(func(cfg commons.CheckConfig, id string) { checkIfModernSKU(cfg, one(Disk{SKU: s}), id) })
	}
	if sku("Premium_LRS") != "OK" || sku("Standard_LRS") != "FAIL" {
		t.Error("sku check")
	}
	disk := one(Disk{ID: "/d1", Name: "d1", Attached: true})
	snap := func(age time.Duration) internal.Fetched[Disk] {
		return one(Disk{Snapshot: true, SourceID: "/D1", Created: time.Now().Add(-age)})
	}
	if statusOf(checkIfRecentSnapshots(disk, snap(time.Hour))) != "OK" ||
		statusOf(checkIfRecentSnapshots(disk, snap(30*24*time.Hour))) != "FAIL" ||
		statusOf(checkIfRecentSnapshots(disk, internal.Fetched[Disk]{})) != "FAIL" ||
		statusOf(checkIfRecentSnapshots(disk, internal.Fetched[Disk]{Err: errors.New("403")})) != "FAIL" {
		t.Error("snapshot check")
	}
}
