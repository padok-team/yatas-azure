package servicebus

import (
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func Test_parseTTLDays(t *testing.T) {
	cases := map[string]float64{"P14D": 14, "PT12H": 0.5, "P1DT12H": 1.5, "P10675199DT2H48M5.4775807S": 10675199 + 2.0/24 + 48.0/1440 + 5.4775807/86400}
	for in, want := range cases {
		if got := parseTTLDays(in); got < want-1e-6 || got > want+1e-6 {
			t.Errorf("%s = %f want %f", in, got, want)
		}
	}
	if parseTTLDays("garbage") < maxRetentionDays {
		t.Error("unknown format must fail the check")
	}
}

func Test_checkIfRetention(t *testing.T) {
	for ttl, want := range map[float64]string{7: "OK", 14: "OK", 30: "FAIL"} {
		in := internal.Fetched[Queue]{Items: []Queue{{Name: "q", TTLDays: ttl}}}
		if got := internal.RunCheck(func(cfg commons.CheckConfig) { checkIfRetention(cfg, in, "t") }); got.Status != want {
			t.Errorf("ttl=%v: %s want %s", ttl, got.Status, want)
		}
	}
}
