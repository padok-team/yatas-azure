package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// GraphBaseURL is the Microsoft Graph v1.0 endpoint. It is a variable so tests
// can point it at an httptest server.
var GraphBaseURL = "https://graph.microsoft.com/v1.0"

const graphScope = "https://graph.microsoft.com/.default"

// Graph is a minimal Microsoft Graph client. Entra ID data lives in Graph, not
// ARM, and needs its own permissions (see README). A thin REST client over the
// shared credential avoids pulling the full Graph SDK.
type Graph struct {
	Credential azcore.TokenCredential
	HTTP       *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// NewGraph builds a Graph client from the session credential.
func NewGraph(s Session) (*Graph, error) {
	if err := s.Valid(); err != nil {
		return nil, err
	}
	return &Graph{Credential: s.Credential, HTTP: http.DefaultClient}, nil
}

// GraphError is a non-2xx answer from Graph.
type GraphError struct {
	Status int
	Path   string
	Body   string
}

func (e *GraphError) Error() string {
	hint := ""
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		hint = " (the identity lacks Entra access: activate a directory role such as Global Reader, or grant the app Graph read permissions with admin consent; guests have none by default)"
	}
	return fmt.Sprintf("Microsoft Graph %s returned %d%s: %s", e.Path, e.Status, hint, e.Body)
}

// IsNotFound reports whether err is a Graph 404 (e.g. a deleted principal).
func IsNotFound(err error) bool {
	var ge *GraphError
	return errors.As(err, &ge) && ge.Status == http.StatusNotFound
}

// bearer returns a cached token: az-cli based credentials spawn a process per
// GetToken call, which is too slow for per-user requests.
func (g *Graph) bearer(ctx context.Context) (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.token != "" && time.Until(g.expiry) > time.Minute {
		return g.token, nil
	}
	token, err := g.Credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{graphScope}})
	if err != nil {
		return "", fmt.Errorf("getting a Microsoft Graph token: %w", err)
	}
	g.token, g.expiry = token.Token, token.ExpiresOn
	return g.token, nil
}

func (g *Graph) get(ctx context.Context, url, path string) ([]byte, error) {
	token, err := g.bearer(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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
		return nil, &GraphError{Status: resp.StatusCode, Path: path, Body: msg}
	}
	return body, nil
}

type graphPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"@odata.nextLink"`
}

// GraphList GETs a Graph collection (path relative to GraphBaseURL, query
// included) and follows @odata.nextLink until exhaustion.
func GraphList[T any](ctx context.Context, g *Graph, path string) ([]T, error) {
	var all []T
	next := GraphBaseURL + path
	for next != "" {
		body, err := g.get(ctx, next, path)
		if err != nil {
			return nil, err
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

// GraphGet GETs a single Graph object.
func GraphGet[T any](ctx context.Context, g *Graph, path string) (T, error) {
	var out T
	body, err := g.get(ctx, GraphBaseURL+path, path)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(body, &out)
	return out, err
}
