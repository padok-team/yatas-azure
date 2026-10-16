package internal

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
)

type fakeCredential struct{}

func (fakeCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "tok", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type item struct {
	ID string `json:"id"`
}

func TestGraphListFollowsNextLink(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing bearer token")
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `{"value":[{"id":"c"}]}`)
			return
		}
		fmt.Fprintf(w, `{"value":[{"id":"a"},{"id":"b"}],"@odata.nextLink":"%s/users?page=2"}`, srv.URL)
	}))
	defer srv.Close()
	GraphBaseURL = srv.URL

	got, err := GraphList[item](context.TODO(), &Graph{Credential: fakeCredential{}, HTTP: srv.Client()}, "/users")
	if err != nil || len(got) != 3 || got[2].ID != "c" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestGraphListSurfacesPermissionErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":"Authorization_RequestDenied"}}`)
	}))
	defer srv.Close()
	GraphBaseURL = srv.URL

	_, err := GraphList[item](context.TODO(), &Graph{Credential: fakeCredential{}, HTTP: srv.Client()}, "/users")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected a 403 error, got %v", err)
	}
}
