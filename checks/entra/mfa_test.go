package entra

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/padok-team/yatas-azure/internal"
)

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "t", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// graphServer fakes the two MFA sources. reportStatus is the answer of the
// registration report; methods maps a user ID to its method types.
func graphServer(reportStatus int, methodsStatus int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/reports/authenticationMethods/userRegistrationDetails/"):
			if reportStatus != 200 {
				w.WriteHeader(reportStatus)
				return
			}
			fmt.Fprint(w, `{"isMfaRegistered": true}`)
		case strings.HasSuffix(r.URL.Path, "/authentication/methods"):
			if methodsStatus != 200 {
				w.WriteHeader(methodsStatus)
				return
			}
			if strings.Contains(r.URL.Path, "/with-mfa/") {
				fmt.Fprint(w, `{"value":[{"@odata.type":"#microsoft.graph.passwordAuthenticationMethod"},{"@odata.type":"#microsoft.graph.phoneAuthenticationMethod"}]}`)
				return
			}
			fmt.Fprint(w, `{"value":[{"@odata.type":"#microsoft.graph.passwordAuthenticationMethod"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func Test_mfaStatuses_usesReportWhenAvailable(t *testing.T) {
	srv := graphServer(200, 403)
	defer srv.Close()
	internal.GraphBaseURL = srv.URL
	g := &internal.Graph{Credential: fakeCred{}, HTTP: srv.Client()}

	got, err := mfaStatuses(context.TODO(), g, []string{"a", "b"})
	if err != nil || !got["a"] || !got["b"] {
		t.Fatalf("got %v, %v", got, err)
	}
}

func Test_mfaStatuses_fallsBackToAuthenticationMethods(t *testing.T) {
	srv := graphServer(403, 200) // e.g. tenant without Entra ID P1
	defer srv.Close()
	internal.GraphBaseURL = srv.URL
	g := &internal.Graph{Credential: fakeCred{}, HTTP: srv.Client()}

	got, err := mfaStatuses(context.TODO(), g, []string{"with-mfa", "password-only"})
	if err != nil {
		t.Fatal(err)
	}
	if !got["with-mfa"] || got["password-only"] {
		t.Errorf("got %v, want with-mfa=true password-only=false", got)
	}
}

// When neither source is readable the error must surface, never "no MFA" nor "MFA".
func Test_mfaStatuses_bothFail(t *testing.T) {
	srv := graphServer(403, 403)
	defer srv.Close()
	internal.GraphBaseURL = srv.URL
	g := &internal.Graph{Credential: fakeCred{}, HTTP: srv.Client()}

	if _, err := mfaStatuses(context.TODO(), g, []string{"a"}); err == nil {
		t.Fatal("expected an error when both MFA sources are denied")
	}
}
