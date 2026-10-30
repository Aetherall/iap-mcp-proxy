package upstream

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/knwoop/iap-mcp-proxy/internal/signin"
)

// fakeServer plays an MCP server that is also its own OAuth
// authorization server, as GitLab's /api/v4/mcp is.
type fakeServer struct {
	*httptest.Server

	mu            sync.Mutex
	registrations []map[string]any
	challenge     string
	issued        map[string]bool
	refreshed     int
}

func newFakeServer(t *testing.T) *fakeServer {
	f := &fakeServer{issued: map[string]bool{}}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)

	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"resource":              f.URL + "/mcp",
			"authorization_servers": []string{f.URL},
			"scopes_supported":      []string{"mcp"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 f.URL,
			"authorization_endpoint": f.URL + "/authorize",
			"token_endpoint":         f.URL + "/token",
			"registration_endpoint":  f.URL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		var registration map[string]any
		json.NewDecoder(r.Body).Decode(&registration)
		f.mu.Lock()
		f.registrations = append(f.registrations, registration)
		f.mu.Unlock()
		writeJSON(w, http.StatusCreated, map[string]any{"client_id": "client-1"})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		f.mu.Lock()
		f.challenge = query.Get("code_challenge")
		f.mu.Unlock()
		if query.Get("client_id") != "client-1" || query.Get("resource") != f.URL+"/mcp" || query.Get("scope") != "mcp" {
			http.Error(w, "unexpected authorization request: "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}
		redirect, _ := url.Parse(query.Get("redirect_uri"))
		redirect.RawQuery = url.Values{"code": {"code-1"}, "state": {query.Get("state")}}.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "code-1" || base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge || r.Form.Get("client_id") != "client-1" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
				return
			}
			f.issued["access-1"] = true
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "access-1", "token_type": "Bearer", "refresh_token": "refresh-1", "expires_in": 3600})
		case "refresh_token":
			if r.Form.Get("refresh_token") != "refresh-1" || r.Form.Get("resource") != f.URL+"/mcp" || r.Form.Get("client_id") != "client-1" {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
				return
			}
			f.refreshed++
			token := fmt.Sprintf("access-refreshed-%d", f.refreshed)
			f.issued[token] = true
			writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "refresh_token": "refresh-1", "expires_in": 3600})
		}
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		accepted := f.issued[trimBearer(r.Header.Get("Authorization"))]
		f.mu.Unlock()
		if !accepted {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+f.URL+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return f
}

// revoke makes the MCP server reject every token issued so far, as
// after a token is revoked server-side.
func (f *fakeServer) revoke() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = map[string]bool{}
}

func (f *fakeServer) snapshot() (registrations []map[string]any, refreshed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.registrations...), f.refreshed
}

func trimBearer(header string) string {
	if len(header) > len("Bearer ") {
		return header[len("Bearer "):]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// followInBrowser plays the user's browser: it follows the
// authorization redirect back to the loopback callback.
func followInBrowser(t *testing.T) signin.Interaction {
	return signin.Interaction{OpenBrowser: func(authorizationURL string) {
		go func() {
			resp, err := http.Get(authorizationURL)
			if err != nil {
				t.Errorf("browser: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}}
}

func setup(t *testing.T) *fakeServer {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	useKeychain = false
	t.Cleanup(func() { useKeychain = true })
	return newFakeServer(t)
}

func newTestSession(t *testing.T, server *fakeServer) *Session {
	session := NewSession(Config{
		Resource: server.URL + "/mcp",
		HTTP:     server.Client(),
		SignIn:   followInBrowser(t),
	})
	t.Cleanup(func() { session.Logout() })
	return session
}

func get(t *testing.T, client *http.Client, target string) int {
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestSignsInThroughDiscoveryAndRegistration(t *testing.T) {
	server := setup(t)
	session := newTestSession(t, server)
	client := &http.Client{Transport: &Transport{Base: server.Client().Transport, Session: session}}

	if status := get(t, client, server.URL+"/mcp"); status != http.StatusOK {
		t.Fatalf("MCP request after sign-in: HTTP %d, want 200", status)
	}
	registrations, _ := server.snapshot()
	if len(registrations) != 1 {
		t.Fatalf("registrations = %d, want 1", len(registrations))
	}
	registration := registrations[0]
	if registration["token_endpoint_auth_method"] != "none" || registration["scope"] != "mcp" {
		t.Errorf("registration = %v, want a public client asking for scope mcp", registration)
	}
}

func TestRetriesWithARefreshedTokenWhenTheServerRejectsIt(t *testing.T) {
	server := setup(t)
	session := newTestSession(t, server)
	client := &http.Client{Transport: &Transport{Base: server.Client().Transport, Session: session}}
	get(t, client, server.URL+"/mcp")

	server.revoke()

	if status := get(t, client, server.URL+"/mcp"); status != http.StatusOK {
		t.Fatalf("MCP request after revocation: HTTP %d, want 200", status)
	}
	if _, refreshed := server.snapshot(); refreshed != 1 {
		t.Errorf("refreshes = %d, want 1", refreshed)
	}
}

func TestReusesStoredCredentialsInANewSession(t *testing.T) {
	server := setup(t)
	newTestSession(t, server).Token(t.Context())

	restarted := NewSession(Config{Resource: server.URL + "/mcp", HTTP: server.Client()})
	token, err := restarted.Token(t.Context())

	if err != nil || token != "access-1" {
		t.Fatalf("restarted session token = %q, %v; want access-1 from the store", token, err)
	}
}

func TestKeepsATokenAnotherRequestAlreadyRefreshed(t *testing.T) {
	server := setup(t)
	session := newTestSession(t, server)
	session.Token(t.Context())

	session.Invalidate("a-token-replaced-since")
	token, err := session.Token(t.Context())

	if _, refreshed := server.snapshot(); err != nil || token != "access-1" || refreshed != 0 {
		t.Fatalf("token = %q, %v after %d refreshes; want access-1 kept", token, err, refreshed)
	}
}

func TestFindsAnIssuerWithAPathPastItsOriginsMetadata(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"issuer": server.URL})
	})
	mux.HandleFunc("/realms/team/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"issuer": server.URL + "/realms/team", "token_endpoint": server.URL + "/realms/team/token"})
	})

	found, err := fetchAuthorizationServer(t.Context(), server.Client(), server.URL+"/realms/team")

	if err != nil || found.TokenEndpoint != server.URL+"/realms/team/token" {
		t.Fatalf("authorization server = %+v, %v; want the realm's metadata", found, err)
	}
}

func TestSignInOutlivesTheRequestThatStartedIt(t *testing.T) {
	server := setup(t)
	session := newTestSession(t, server)
	client := &http.Client{Transport: &Transport{Base: server.Client().Transport, Session: session}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/mcp", nil)

	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
	}

	session.mu.Lock()
	signedIn := session.state != nil && session.state.Token != nil
	session.mu.Unlock()
	if !signedIn {
		t.Fatal("the sign-in a canceled request started was abandoned")
	}
}

func TestFailsAtOnceWithoutAWayToSignIn(t *testing.T) {
	server := setup(t)
	session := NewSession(Config{Resource: server.URL + "/mcp", HTTP: server.Client()})

	_, err := session.Token(t.Context())

	if registrations, _ := server.snapshot(); !errors.Is(err, signin.ErrNoBrowser) || len(registrations) != 0 {
		t.Fatalf("Token = %v after %d registrations; want ErrNoBrowser before registering", err, len(registrations))
	}
}
