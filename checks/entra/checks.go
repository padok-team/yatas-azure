package entra

import (
	"fmt"
	"time"

	"github.com/padok-team/yatas-azure/internal"
	"github.com/padok-team/yatas/plugins/commons"
)

// Check IDs are unique and stable: users reference them in `.yatas.yml`.
//
// AZURE_ENT_002 (MFA, mirroring AWS "IAM Users have 2FA activated") is
// intentionally absent and its ID must not be reused: MFA can't be verified on
// Azure with the permissions a delegated `az login` has (see README). The
// implementation lives in git history, commit a77df76.
const (
	NoInteractiveSignInID = "AZURE_ENT_001"
	PasswordPolicyID      = "AZURE_ENT_003"
	CredentialAgeID       = "AZURE_ENT_004"
)

// MaxCredentialAge is the rotation deadline for secrets and certificates.
const MaxCredentialAge = 90 * 24 * time.Hour

// MaxPasswordValidityDays is the longest accepted password expiration period.
const MaxPasswordValidityDays = 365

// MaxLockoutThreshold is the highest accepted smart-lockout threshold.
const MaxLockoutThreshold = 10

// AZURE_ENT_001 (≈ AWS "IAM Non-human users don't have console password"). A
// non-human identity must not be given interactive sign-in credentials: an
// enterprise application configured for password-based SSO stores user
// credentials that are replayed at sign-in. Managed identities have none.
func checkIfNoInteractiveSignIn(checkConfig commons.CheckConfig, sps internal.Fetched[ServicePrincipal], testName string) {
	check := internal.NewHDSCheck("Entra non-human identities with access to the subscription don't have interactive sign-in credentials", "Check that service principals holding a role assignment on the subscription are not configured with password-based SSO", testName)
	if sps.Failed(&check, "Entra service principals") {
		checkConfig.Queue <- check
		return
	}
	for _, sp := range sps.Items {
		if sp.SSOMode == "password" {
			internal.Fail(&check, sp.ID, "Service principal "+sp.DisplayName+" uses password-based SSO (interactive sign-in credentials)")
		} else {
			internal.Pass(&check, sp.ID, "Service principal "+sp.DisplayName+" has no interactive sign-in credentials")
		}
	}
	checkConfig.Queue <- check
}

// AZURE_ENT_003 (≈ AWS "IAM password policy must be defined and enforced").
// Federated domains delegate the policy to the identity provider. Managed
// domains need an expiration of at most MaxPasswordValidityDays, and any custom
// smart-lockout threshold must be at most MaxLockoutThreshold.
func checkIfPasswordPolicy(checkConfig commons.CheckConfig, policies internal.Fetched[PasswordPolicy], testName string) {
	check := internal.NewHDSCheck("Entra password policy must be defined and enforced", fmt.Sprintf("Check that the domains of the subscription users: managed domains expire passwords within %d days and that smart lockout triggers after at most %d failures", MaxPasswordValidityDays, MaxLockoutThreshold), testName)
	if policies.Failed(&check, "Entra password policy") {
		checkConfig.Queue <- check
		return
	}
	for _, p := range policies.Items {
		for _, d := range p.Domains {
			switch {
			case d.Federated:
				internal.Pass(&check, d.Name, "Domain "+d.Name+" is federated: the password policy is enforced by the identity provider")
			case d.ValidityDays == NeverExpires || d.ValidityDays > MaxPasswordValidityDays:
				internal.Fail(&check, d.Name, fmt.Sprintf("Domain %s passwords never expire or expire after more than %d days", d.Name, MaxPasswordValidityDays))
			default:
				internal.Pass(&check, d.Name, fmt.Sprintf("Domain %s passwords expire after %d days", d.Name, d.ValidityDays))
			}
		}
		if p.LockoutThreshold > MaxLockoutThreshold {
			internal.Fail(&check, "smart-lockout", fmt.Sprintf("Smart lockout threshold is %d, at most %d is required", p.LockoutThreshold, MaxLockoutThreshold))
		} else {
			internal.Pass(&check, "smart-lockout", "Smart lockout threshold is within the baseline")
		}
	}
	checkConfig.Queue <- check
}

// AZURE_ENT_004 (≈ AWS "IAM access key younger than 90 days"): every active
// client secret / certificate of an app registration was created less than 90
// days ago. Expired credentials are ignored, `now` is injected for the tests.
func checkIfCredentialsYoungerThan90Days(checkConfig commons.CheckConfig, apps internal.Fetched[Application], testName string, now func() time.Time) {
	check := internal.NewHDSCheck("Entra application secrets and certificates younger than 90 days", "Check that active client secrets and certificates of the app registrations with access to the subscription were created less than 90 days ago", testName)
	if apps.Failed(&check, "Entra app registrations") {
		checkConfig.Queue <- check
		return
	}
	for _, app := range apps.Items {
		hasActive, failed := false, false
		for _, c := range app.Credentials {
			if c.End != nil && c.End.Before(now()) {
				continue // expired credentials can't be used
			}
			hasActive = true
			label := fmt.Sprintf("%s %q of application %s", c.Kind, c.Name, app.DisplayName)
			switch {
			case c.Start == nil:
				internal.Fail(&check, app.ID, label+" has no start date, its age can't be established")
				failed = true
			case now().Sub(*c.Start) > MaxCredentialAge:
				internal.Fail(&check, app.ID, fmt.Sprintf("%s is %d days old, rotate it within 90 days", label, int(now().Sub(*c.Start).Hours()/24)))
				failed = true
			}
		}
		if hasActive && !failed {
			internal.Pass(&check, app.ID, "Credentials of application "+app.DisplayName+" are younger than 90 days")
		}
	}
	checkConfig.Queue <- check
}
