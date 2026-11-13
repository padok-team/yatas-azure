package defender

import (
	"errors"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_checkIfNoHighAlerts(t *testing.T) {
	cases := []struct {
		in   internal.Fetched[Alert]
		want string
	}{
		{internal.Fetched[Alert]{}, "OK"},
		{internal.Fetched[Alert]{Items: []Alert{{Severity: "Low", Status: "Active"}, {Severity: "High", Status: "Dismissed"}}}, "OK"},
		{internal.Fetched[Alert]{Items: []Alert{{Severity: "High", Status: "Active"}}}, "FAIL"},
		{internal.Fetched[Alert]{Err: errors.New("403")}, "FAIL"},
	}
	for i, c := range cases {
		got := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfNoHighAlerts(cfg, c.in, "t") })
		if got.Status != c.want {
			t.Errorf("case %d: %s want %s", i, got.Status, c.want)
		}
	}
}
