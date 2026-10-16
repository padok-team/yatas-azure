package entra

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

const (
	defDelete = "/providers/Microsoft.Authorization/policyDefinitions/" + mfaPolicyDeleteID
	defWrite  = "/providers/Microsoft.Authorization/policyDefinitions/" + mfaPolicyWriteID
)

func Test_policyEnforcement(t *testing.T) {
	full := func(def string) policyAssignment {
		return policyAssignment{DefinitionID: def, Enforced: true, Effect: "Deny"}
	}
	cases := []struct {
		name string
		in   []policyAssignment
		want bool
		note string // substring expected in the notes
	}{
		{"both denied", []policyAssignment{full(defDelete), full(defWrite)}, true, ""},
		{"DenyAction effect counts", []policyAssignment{{DefinitionID: defDelete, Enforced: true, Effect: "DenyAction"}, full(defWrite)}, true, ""},
		{"nothing assigned", nil, false, "no Azure Policy MFA enforcement"},
		{"unrelated assignment", []policyAssignment{{DefinitionID: "/x/other", Enforced: true, Effect: "Deny"}}, false, "no Azure Policy MFA enforcement"},
		{"only write", []policyAssignment{full(defWrite)}, false, ""},
		{"audit only", []policyAssignment{{DefinitionID: defDelete, Enforced: true, Effect: "AuditAction"}, full(defWrite)}, false, "audit does not enforce"},
		{"do not enforce", []policyAssignment{{DefinitionID: defDelete, Enforced: false, Effect: "Deny"}, full(defWrite)}, false, "DoNotEnforce"},
		{"regional rollout only", []policyAssignment{{DefinitionID: defDelete, Enforced: true, Effect: "Deny", Partial: true}, full(defWrite)}, false, "part of the resources"},
		{"a full assignment wins over a partial one", []policyAssignment{{DefinitionID: defDelete, Enforced: true, Effect: "Deny", Partial: true}, full(defDelete), full(defWrite)}, true, ""},
	}
	for _, c := range cases {
		got, notes := policyEnforcement(c.in)
		if got != c.want {
			t.Errorf("%s: enforced = %v, want %v (%v)", c.name, got, c.want, notes)
		}
		if c.note != "" && !strings.Contains(strings.Join(notes, ";"), c.note) {
			t.Errorf("%s: notes %v should mention %q", c.name, notes, c.note)
		}
	}
}

func caFrom(t *testing.T, raw string) CAPolicy {
	t.Helper()
	var j caJSON
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		t.Fatal(err)
	}
	return toCAPolicy(j)
}

// goodCA is "require MFA, all users, all apps", the simplest enforcing policy.
const goodCA = `{"displayName":"mfa-all","state":"enabled",
 "conditions":{"users":{"includeUsers":["All"]},"applications":{"includeApplications":["All"]}},
 "grantControls":{"operator":"OR","builtInControls":["mfa"]}}`

func Test_CAPolicy_covers(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		user   string
		groups map[string]bool
		want   bool
	}{
		{"all users all apps mfa", goodCA, "u1", nil, true},
		{"azure management app only", strings.Replace(goodCA, `["All"]},"applications"`, `["All"]},"applications"`, 1), "u1", nil, true},
		{"report-only is not enforcement", strings.Replace(goodCA, `"enabled"`, `"enabledForReportingButNotEnforced"`, 1), "u1", nil, false},
		{"disabled", strings.Replace(goodCA, `"enabled"`, `"disabled"`, 1), "u1", nil, false},
		{"azure management targeted explicitly", strings.Replace(goodCA, `"includeApplications":["All"]`, `"includeApplications":["797f4846-ba00-4fd7-ba43-dac1f8f63013"]`, 1), "u1", nil, true},
		{"other app only", strings.Replace(goodCA, `"includeApplications":["All"]`, `"includeApplications":["00000003-0000-0000-c000-000000000000"]`, 1), "u1", nil, false},
		{"azure management excluded", strings.Replace(goodCA, `"applications":{"includeApplications":["All"]}`, `"applications":{"includeApplications":["All"],"excludeApplications":["797f4846-ba00-4fd7-ba43-dac1f8f63013"]}`, 1), "u1", nil, false},
		{"scoped to a group", strings.Replace(goodCA, `"includeUsers":["All"]`, `"includeUsers":[],"includeGroups":["g"]`, 1), "u1", nil, false},
		{"user excluded", strings.Replace(goodCA, `"includeUsers":["All"]`, `"includeUsers":["All"],"excludeUsers":["U1"]`, 1), "u1", nil, false},
		{"other user excluded", strings.Replace(goodCA, `"includeUsers":["All"]`, `"includeUsers":["All"],"excludeUsers":["u2"]`, 1), "u1", nil, true},
		{"member of an excluded group", strings.Replace(goodCA, `"includeUsers":["All"]`, `"includeUsers":["All"],"excludeGroups":["G1"]`, 1), "u1", map[string]bool{"g1": true}, false},
		{"not member of the excluded group", strings.Replace(goodCA, `"includeUsers":["All"]`, `"includeUsers":["All"],"excludeGroups":["g1"]`, 1), "u1", map[string]bool{"g2": true}, true},
		{"roles excluded", strings.Replace(goodCA, `"includeUsers":["All"]`, `"includeUsers":["All"],"excludeRoles":["role"]`, 1), "u1", nil, false},
		{"mfa or compliant device", strings.Replace(goodCA, `["mfa"]`, `["mfa","compliantDevice"]`, 1), "u1", nil, false},
		{"mfa and compliant device", strings.Replace(strings.Replace(goodCA, `["mfa"]`, `["mfa","compliantDevice"]`, 1), `"OR"`, `"AND"`, 1), "u1", nil, true},
		{"authentication strength", strings.Replace(goodCA, `"builtInControls":["mfa"]`, `"builtInControls":[],"authenticationStrength":{"id":"x"}`, 1), "u1", nil, true},
		{"block instead of mfa", strings.Replace(goodCA, `["mfa"]`, `["block"]`, 1), "u1", nil, false},
		{"trusted locations excluded", strings.Replace(goodCA, `"applications":{"includeApplications":["All"]}`, `"applications":{"includeApplications":["All"]},"locations":{"includeLocations":["All"],"excludeLocations":["AllTrusted"]}`, 1), "u1", nil, false},
		{"risk based", strings.Replace(goodCA, `"applications":{"includeApplications":["All"]}`, `"applications":{"includeApplications":["All"]},"signInRiskLevels":["high"]`, 1), "u1", nil, false},
		{"platform limited", strings.Replace(goodCA, `"applications":{"includeApplications":["All"]}`, `"applications":{"includeApplications":["All"]},"platforms":{"includePlatforms":["android"]}`, 1), "u1", nil, false},
	}
	for _, c := range cases {
		if got := caFrom(t, c.raw).covers(c.user, c.groups); got != c.want {
			t.Errorf("%s: covers = %v, want %v", c.name, got, c.want)
		}
	}
}

func Test_checkIfMFA(t *testing.T) {
	member := User{ID: "m", UPN: "m@x.com"}
	guest := User{ID: "g", UPN: "g_x.com#EXT#@t.onmicrosoft.com", Guest: true}
	run := func(users []User, ev MFAEvidence) commons.Check {
		in := MFAInput{Users: internal.Fetched[User]{Items: users}, Evidence: ev}
		return internal.RunCheck(func(cfg commons.CheckConfig) { checkIfMFA(cfg, in, "test") })
	}

	// Enforced by a policy: passes without any per-user data, and says why.
	c := run([]User{member, guest}, MFAEvidence{ByUser: map[string]UserMFA{"m": {Source: "Security Defaults"}, "g": {Source: "Security Defaults"}}})
	assertStatus(t, c, "OK")
	if !strings.Contains(c.Results[0].Message, "Security Defaults") {
		t.Errorf("the enforcing source should be named: %s", c.Results[0].Message)
	}

	// Not enforced but registered.
	assertStatus(t, run([]User{member}, MFAEvidence{ByUser: map[string]UserMFA{"m": {Registered: true}}}), "OK")

	// Nothing enforces it and nothing registered, everything readable: a real gap.
	c = run([]User{member}, MFAEvidence{ByUser: map[string]UserMFA{"m": {}}, Notes: []string{"no Conditional Access policy"}})
	assertStatus(t, c, "FAIL")
	if !strings.Contains(c.Results[0].Message, "nothing enforces it") {
		t.Errorf("a real gap should say so: %s", c.Results[0].Message)
	}

	// A source was unreadable: reported as unconfirmed, never as a pass.
	c = run([]User{member}, MFAEvidence{ByUser: map[string]UserMFA{"m": {}}, Unconfirmed: true, Notes: []string{"Security Defaults unreadable: 403"}})
	assertStatus(t, c, "FAIL")
	if !strings.Contains(c.Results[0].Message, "could not be confirmed") || !strings.Contains(c.Results[0].Message, "403") {
		t.Errorf("unreadable sources should be reported: %s", c.Results[0].Message)
	}

	// Mixed users: one enforced, one not.
	c = run([]User{member, guest}, MFAEvidence{ByUser: map[string]UserMFA{"m": {Source: "Conditional Access policy p"}, "g": {}}})
	assertStatus(t, c, "FAIL")
	if !strings.Contains(c.Results[1].Message, "Guest user") || !strings.Contains(c.Results[1].Message, "home tenant") {
		t.Errorf("a guest failure should be labelled and explained: %s", c.Results[1].Message)
	}

	// Failure to list the users at all.
	assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) {
		checkIfMFA(cfg, MFAInput{Users: internal.Fetched[User]{Err: errors.New("403")}}, "t")
	}), "FAIL")
}

func Test_briefErr(t *testing.T) {
	ge := &internal.GraphError{Status: 403, Path: "/users/dab35604-5e97-4d33-93e7-66a40cada4a0/authentication/methods?$top=1", Body: "{big json}"}
	if got := briefErr(ge); got != "/users/{id}/authentication/methods returned 403" {
		t.Errorf("briefErr = %q", got)
	}
	if got := briefErr(errors.New("line one\nline two")); got != "line one" {
		t.Errorf("briefErr = %q", got)
	}
}
