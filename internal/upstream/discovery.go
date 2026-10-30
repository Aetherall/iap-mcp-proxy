package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// protectedResource is the RFC 9728 metadata of the upstream MCP server.
type protectedResource struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// authorizationServer is the RFC 8414 (or OpenID Connect discovery)
// metadata of the server that issues tokens for it.
type authorizationServer struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

func discover(ctx context.Context, client *http.Client, resourceURL string) (*protectedResource, *authorizationServer, error) {
	resource, err := fetchProtectedResource(ctx, client, resourceURL)
	if err != nil {
		return nil, nil, err
	}
	if len(resource.AuthorizationServers) == 0 {
		return nil, nil, errors.New("protected resource metadata names no authorization server")
	}
	server, err := fetchAuthorizationServer(ctx, client, resource.AuthorizationServers[0])
	if err != nil {
		return nil, nil, err
	}
	if server.AuthorizationEndpoint == "" || server.TokenEndpoint == "" {
		return nil, nil, fmt.Errorf("authorization server %s advertises no authorization or token endpoint", server.Issuer)
	}
	return resource, server, nil
}

// fetchProtectedResource tries the path-specific well-known URI first,
// then the origin's (RFC 9728 section 3.1), and checks the document
// describes this resource.
func fetchProtectedResource(ctx context.Context, client *http.Client, resourceURL string) (*protectedResource, error) {
	var lastErr error
	for _, candidate := range wellKnownURLs(resourceURL, "oauth-protected-resource") {
		var resource protectedResource
		if err := getJSON(ctx, client, candidate, &resource); err != nil {
			lastErr = err
			continue
		}
		if !describes(resource.Resource, resourceURL) {
			return nil, fmt.Errorf("protected resource metadata at %s describes %q, not %s", candidate, resource.Resource, resourceURL)
		}
		return &resource, nil
	}
	return nil, fmt.Errorf("no protected resource metadata: %w", lastErr)
}

func fetchAuthorizationServer(ctx context.Context, client *http.Client, issuer string) (*authorizationServer, error) {
	var lastErr error
	candidates := append(wellKnownURLs(issuer, "oauth-authorization-server"), wellKnownURLs(issuer, "openid-configuration")...)
	candidates = append(candidates, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration")
	for _, candidate := range candidates {
		var server authorizationServer
		if err := getJSON(ctx, client, candidate, &server); err != nil {
			lastErr = err
			continue
		}
		if strings.TrimSuffix(server.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
			return nil, fmt.Errorf("authorization server metadata at %s names issuer %q, not %s", candidate, server.Issuer, issuer)
		}
		return &server, nil
	}
	return nil, fmt.Errorf("no authorization server metadata for %s: %w", issuer, lastErr)
}

// wellKnownURLs inserts /.well-known/<name> between the origin and the
// path (RFC 8414 section 3.1), then falls back to the origin alone.
func wellKnownURLs(rawURL, name string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	if path == "" {
		return []string{origin + "/.well-known/" + name}
	}
	return []string{origin + "/.well-known/" + name + path, origin + "/.well-known/" + name}
}

// describes reports whether metadata naming resource applies to
// resourceURL: the same URL, or a prefix of it on the same origin.
func describes(resource, resourceURL string) bool {
	resource = strings.TrimSuffix(resource, "/")
	return resource != "" && (resource == strings.TrimSuffix(resourceURL, "/") || strings.HasPrefix(resourceURL, resource+"/"))
}

func getJSON(ctx context.Context, client *http.Client, target string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", target, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into)
}

type registeredClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// register creates a public client for this redirect URI (RFC 7591).
func register(ctx context.Context, client *http.Client, server *authorizationServer, name, redirectURI string, scopes []string) (*registeredClient, error) {
	if server.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("authorization server %s does not support dynamic client registration; configure a client with --upstream-oauth-client-id", server.Issuer)
	}
	body, err := json.Marshal(map[string]any{
		"client_name":                name,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"application_type":           "native",
		"scope":                      strings.Join(scopes, " "),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registering a client: %w", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registering a client: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}
	var registered registeredClient
	if err := json.Unmarshal(payload, &registered); err != nil {
		return nil, fmt.Errorf("decoding client registration: %w", err)
	}
	if registered.ClientID == "" {
		return nil, errors.New("client registration returned no client_id")
	}
	return &registered, nil
}
