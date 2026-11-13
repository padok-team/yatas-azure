package vmss

import (
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_checkIfMultiZone(t *testing.T) {
	for zones, want := range map[int]string{0: "FAIL", 1: "FAIL", 3: "OK"} {
		in := internal.Fetched[ScaleSet]{Items: []ScaleSet{{Name: "s", Zones: zones}}}
		if got := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfMultiZone(cfg, in, "t") }); got.Status != want {
			t.Errorf("zones=%d: %s want %s", zones, got.Status, want)
		}
	}
}
