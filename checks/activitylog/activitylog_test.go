package activitylog

import (
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_checkIfExported(t *testing.T) {
	for exported, want := range map[bool]string{true: "OK", false: "FAIL"} {
		in := internal.Fetched[Subscription]{Items: []Subscription{{ID: "s", Exported: exported}}}
		if got := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfExported(cfg, in, "t") }); got.Status != want {
			t.Errorf("exported=%v: %s want %s", exported, got.Status, want)
		}
	}
}
