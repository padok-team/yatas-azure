package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// GraphBaseURL is the Microsoft Graph v1.0 endpoint. It is a variable so tests
// can point it at an httptest server.
var GraphBaseURL = "https://graph.microsoft.com/v1.0"

const graphScope = "https://graph.microsoft.com/.default"

// Graph is a minimal Microsoft Graph client. Entra ID data lives in Graph, not
// ARM, and needs its own application permissions (see README). A thin REST
// client over the shared credential avoids pulling the full Graph SDK.
type Graph struct {
	Credential azcore.TokenCredential
	HTTP       *http.Client
}

// NewGraph builds a Graph client from the session credential.
func NewGraph(s Session) (*Graph, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	return &Graph{Credential: s.Credential, HTTP: http.DefaultClient}, nil
}

type graphPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// GraphList GETs a Graph collection (path relative to GraphBaseURL, query
// included) and follows @odata.nextLink until exhaustion.
func GraphList[T any](ctx context.Context, g *Graph, path string) ([]T, error) {
	token, err := g.Credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{graphScope}})
	if err != nil {
		return nil, fmt.Errorf("getting a Microsoft Graph token: %w", err)
	}
	var all []T
	next := GraphBaseURL + path
	for next != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := g.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			msg := strings.TrimSpace(string(body))
			if len(msg) > 300 {
				msg = msg[:300] + "..."
			}
			hint := ""
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				hint = " (the identity lacks Entra access: activate a directory role such as Global Reader, or grant the app Graph read permissions with admin consent; guests have none by default)"
			}
			return nil, fmt.Errorf("Microsoft Graph %s returned %d%s: %s", path, resp.StatusCode, hint, msg)
		}
		var page graphPage[T]
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
		next = page.NextLink
	}
	return all, nil
}
