package entra

import (
	"errors"
	"testing"
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

func assertStatus(t *testing.T, check commons.Check, want string) {
	t.Helper()
	if check.Status != want {
		t.Errorf("status = %s, want %s (%+v)", check.Status, want, check.Results)
	}
	if check.Categories[len(check.Categories)-1] != "HDS" {
		t.Errorf("not tagged HDS: %v", check.Categories)
	}
}

func Test_checkIfNoInteractiveSignIn(t *testing.T) {
	run := func(sp ServicePrincipal, want string) {
		in := internal.Fetched[ServicePrincipal]{Items: []ServicePrincipal{sp}}
		assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) { checkIfNoInteractiveSignIn(cfg, in, "test") }), want)
	}
	run(ServicePrincipal{DisplayName: "a", Type: "Application", SSOMode: "saml"}, "OK")
	run(ServicePrincipal{DisplayName: "mi", Type: "ManagedIdentity"}, "OK")
	run(ServicePrincipal{DisplayName: "a", Type: "Application", SSOMode: "password"}, "FAIL")
}

func Test_checkIfMFA(t *testing.T) {
	run := func(u User, want string) {
		in := internal.Fetched[User]{Items: []User{u}}
		assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) { checkIfMFA(cfg, in, "test") }), want)
	}
	run(User{UPN: "a@x", MFARegistered: true}, "OK")
	run(User{UPN: "a@x"}, "FAIL")
}

func Test_checkIfPasswordPolicy(t *testing.T) {
	run := func(p PasswordPolicy, want string) {
		in := internal.Fetched[PasswordPolicy]{Items: []PasswordPolicy{p}}
		assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) { checkIfPasswordPolicy(cfg, in, "test") }), want)
	}
	run(PasswordPolicy{Domains: []Domain{{Name: "a.com", ValidityDays: 90}}}, "OK")
	run(PasswordPolicy{Domains: []Domain{{Name: "a.com", Federated: true, ValidityDays: NeverExpires}}}, "OK")
	run(PasswordPolicy{Domains: []Domain{{Name: "a.com", ValidityDays: NeverExpires}}}, "FAIL")
	run(PasswordPolicy{Domains: []Domain{{Name: "a.com", ValidityDays: 90}}, LockoutThreshold: 50}, "FAIL")
}

func Test_checkIfCredentialsYoungerThan90Days(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	ago := func(d int) *time.Time { v := now.AddDate(0, 0, -d); return &v }
	ahead := func(d int) *time.Time { v := now.AddDate(0, 0, d); return &v }
	run := func(app Application, want string) {
		in := internal.Fetched[Application]{Items: []Application{app}}
		assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) {
			checkIfCredentialsYoungerThan90Days(cfg, in, "test", func() time.Time { return now })
		}), want)
	}
	run(Application{DisplayName: "a", Credentials: []Credential{{Kind: "secret", Start: ago(10), End: ahead(80)}}}, "OK")
	run(Application{DisplayName: "a", Credentials: []Credential{{Kind: "secret", Start: ago(200), End: ahead(100)}}}, "FAIL")
	// An old but expired secret can't be used: it is ignored.
	run(Application{DisplayName: "a", Credentials: []Credential{{Kind: "secret", Start: ago(400), End: ago(30)}, {Kind: "certificate", Start: ago(5), End: ahead(300)}}}, "OK")
	run(Application{DisplayName: "a", Credentials: []Credential{{Kind: "secret", Start: nil, End: ahead(30)}}}, "FAIL")
}

// A Graph permission failure must never be reported as compliant.
func Test_fetchErrorFails(t *testing.T) {
	err := errors.New("Microsoft Graph returned 403")
	assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) {
		checkIfNoInteractiveSignIn(cfg, internal.Fetched[ServicePrincipal]{Err: err}, "t")
	}), "FAIL")
	assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) { checkIfMFA(cfg, internal.Fetched[User]{Err: err}, "t") }), "FAIL")
	assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) {
		checkIfPasswordPolicy(cfg, internal.Fetched[PasswordPolicy]{Err: err}, "t")
	}), "FAIL")
	assertStatus(t, internal.RunCheck(func(cfg commons.CheckConfig) {
		checkIfCredentialsYoungerThan90Days(cfg, internal.Fetched[Application]{Err: err}, "t", time.Now)
	}), "FAIL")
}

func Test_mfaCapable(t *testing.T) {
	cases := []struct {
		name  string
		types []string
		want  bool
	}{
		{"password only", []string{"#microsoft.graph.passwordAuthenticationMethod"}, false},
		{"password and email", []string{"#microsoft.graph.passwordAuthenticationMethod", "#microsoft.graph.emailAuthenticationMethod"}, false},
		{"temporary access pass", []string{"#microsoft.graph.temporaryAccessPassAuthenticationMethod"}, false},
		{"authenticator", []string{"#microsoft.graph.passwordAuthenticationMethod", "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}, true},
		{"phone", []string{"#microsoft.graph.phoneAuthenticationMethod"}, true},
		{"fido2", []string{"#microsoft.graph.fido2AuthenticationMethod"}, true},
		{"none", nil, false},
	}
	for _, c := range cases {
		if got := mfaCapable(c.types); got != c.want {
			t.Errorf("%s: mfaCapable = %v, want %v", c.name, got, c.want)
		}
	}
}

func Test_domainOf(t *testing.T) {
	if got := domainOf("Jane.Doe@Contoso.COM"); got != "contoso.com" {
		t.Errorf("domainOf = %q", got)
	}
	if got := domainOf("no-at-sign"); got != "" {
		t.Errorf("domainOf = %q, want empty", got)
	}
}
