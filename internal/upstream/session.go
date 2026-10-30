// Package upstream signs in to the MCP server behind IAP with that
// server's own OAuth, as the MCP authorization spec describes it:
// protected resource metadata (RFC 9728), authorization server metadata
// (RFC 8414), dynamic client registration (RFC 7591) unless a client is
// configured, and the authorization code flow with PKCE. Every request
// it sends, discovery and token requests included, goes through the IAP
// transport, so IAP and the application each get their own credential:
// IAP's in Proxy-Authorization, the application's in Authorization.
package upstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// OpenBrowser opens a URL in the user's browser, best effort.
type OpenBrowser func(url string)

// Config configures the sign-in to one upstream MCP server.
type Config struct {
	// Resource is the upstream MCP endpoint URL; tokens are bound to it.
	Resource string
	// ClientID and ClientSecret name a client registered with the
	// authorization server beforehand. Without a ClientID the session
	// registers one dynamically.
	ClientID     string
	ClientSecret string
	// CallbackPort fixes the loopback redirect port, for a pre-registered
	// client whose redirect URI names one. Zero picks a free port.
	CallbackPort int
	// Scopes overrides the scopes the protected resource advertises.
	Scopes []string
	// ClientName is sent when registering dynamically.
	ClientName string
	// HTTP sends discovery, registration and token requests; it must go
	// through IAP.
	HTTP        *http.Client
	OpenBrowser OpenBrowser
	Logger      *slog.Logger
}

// Session holds the upstream OAuth credentials for one resource and
// keeps them fresh. It is safe for concurrent use; sign-ins and
// refreshes are serialized.
type Session struct {
	cfg   Config
	store *store

	mu    sync.Mutex
	state *storedState
}

// storedState is what a sign-in leaves behind: enough to refresh the
// token without discovery, and to sign in again with the same client.
type storedState struct {
	Resource              string        `json:"resource"`
	AuthorizationEndpoint string        `json:"authorization_endpoint"`
	TokenEndpoint         string        `json:"token_endpoint"`
	Scopes                []string      `json:"scopes,omitempty"`
	ClientID              string        `json:"client_id"`
	RegisteredSecret      string        `json:"registered_client_secret,omitempty"`
	RedirectURI           string        `json:"redirect_uri"`
	Token                 *oauth2.Token `json:"token,omitempty"`
}

// NewSession returns a session that loads stored credentials lazily.
func NewSession(cfg Config) *Session {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ClientName == "" {
		cfg.ClientName = "iap-mcp-proxy"
	}
	return &Session{cfg: cfg, store: newStore(cfg.Resource, cfg.Logger)}
}

// Token returns a valid access token, refreshing it or running the
// browser sign-in when needed.
func (s *Session) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == nil {
		s.state = s.store.load()
	}
	if s.state != nil && s.state.Token != nil {
		if s.state.Token.Valid() {
			return s.state.Token.AccessToken, nil
		}
		if err := s.refresh(ctx); err == nil {
			return s.state.Token.AccessToken, nil
		} else {
			s.cfg.Logger.Warn("upstream OAuth refresh failed; signing in again", "error", err)
		}
	}
	if err := s.signIn(ctx); err != nil {
		return "", err
	}
	return s.state.Token.AccessToken, nil
}

// Invalidate marks the current access token expired, so the next Token
// call refreshes it. Used after the upstream rejects it.
func (s *Session) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil && s.state.Token != nil {
		s.state.Token.Expiry = time.Unix(1, 0)
	}
}

// Logout deletes the stored credentials.
func (s *Session) Logout() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = nil
	return s.store.delete()
}

func (s *Session) oauthConfig() *oauth2.Config {
	secret := s.cfg.ClientSecret
	if s.cfg.ClientID == "" {
		secret = s.state.RegisteredSecret
	}
	style := oauth2.AuthStyleAutoDetect
	if secret == "" {
		style = oauth2.AuthStyleInParams
	}
	return &oauth2.Config{
		ClientID:     s.state.ClientID,
		ClientSecret: secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   s.state.AuthorizationEndpoint,
			TokenURL:  s.state.TokenEndpoint,
			AuthStyle: style,
		},
		RedirectURL: s.state.RedirectURI,
		Scopes:      s.state.Scopes,
	}
}

func (s *Session) httpContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, s.cfg.HTTP)
}

func (s *Session) refresh(ctx context.Context) error {
	if s.state.Token.RefreshToken == "" {
		return errors.New("no refresh token")
	}
	stale := *s.state.Token
	stale.Expiry = time.Unix(1, 0)
	tok, err := s.oauthConfig().TokenSource(s.httpContext(ctx), &stale).Token()
	if err != nil {
		return err
	}
	s.state.Token = tok
	s.store.save(s.state)
	return nil
}

func (s *Session) signIn(ctx context.Context) error {
	resource, server, err := discover(ctx, s.cfg.HTTP, s.cfg.Resource)
	if err != nil {
		return fmt.Errorf("discovering how to sign in to %s: %w", s.cfg.Resource, err)
	}
	scopes := s.cfg.Scopes
	if len(scopes) == 0 {
		scopes = resource.ScopesSupported
	}

	listener, redirectURI, err := s.callbackListener()
	if err != nil {
		return err
	}
	defer listener.Close()

	state := &storedState{
		Resource:              s.cfg.Resource,
		AuthorizationEndpoint: server.AuthorizationEndpoint,
		TokenEndpoint:         server.TokenEndpoint,
		Scopes:                scopes,
		ClientID:              s.cfg.ClientID,
		RedirectURI:           redirectURI,
	}
	switch {
	case s.cfg.ClientID != "":
	case s.reusableRegistration(server, redirectURI):
		state.ClientID = s.state.ClientID
		state.RegisteredSecret = s.state.RegisteredSecret
	default:
		registered, err := register(s.httpContext(ctx), s.cfg.HTTP, server, s.cfg.ClientName, redirectURI, scopes)
		if err != nil {
			return err
		}
		state.ClientID, state.RegisteredSecret = registered.ClientID, registered.ClientSecret
	}
	s.state = state

	tok, err := s.authorize(ctx, listener)
	if err != nil {
		return err
	}
	s.state.Token = tok
	s.store.save(s.state)
	return nil
}

// reusableRegistration reports whether the client registered in an
// earlier sign-in still fits: same authorization server, same redirect.
func (s *Session) reusableRegistration(server *authorizationServer, redirectURI string) bool {
	previous := s.state
	return previous != nil && previous.ClientID != "" &&
		previous.TokenEndpoint == server.TokenEndpoint &&
		previous.RedirectURI == redirectURI
}

// callbackListener listens on the loopback port the redirect URI names:
// the configured one, else the one a previous dynamic registration
// used, else any free port.
func (s *Session) callbackListener() (net.Listener, string, error) {
	port := s.cfg.CallbackPort
	if port == 0 && s.cfg.ClientID == "" && s.state != nil {
		port = loopbackPort(s.state.RedirectURI)
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil && port != 0 && s.cfg.CallbackPort == 0 {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return nil, "", fmt.Errorf("starting OAuth callback listener: %w", err)
	}
	return listener, fmt.Sprintf("http://%s/callback", listener.Addr().String()), nil
}

func (s *Session) authorize(ctx context.Context, listener net.Listener) (*oauth2.Token, error) {
	cfg := s.oauthConfig()
	state := oauth2.GenerateVerifier()
	verifier := oauth2.GenerateVerifier()
	resourceParam := oauth2.SetAuthURLParam("resource", s.cfg.Resource)
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), resourceParam)

	code, err := waitForCode(ctx, listener, state, func() {
		fmt.Fprintf(os.Stderr, "iap-mcp-proxy: opening browser to sign in to %s.\nIf it does not open, visit:\n%s\n", s.cfg.Resource, authURL)
		if s.cfg.OpenBrowser != nil {
			s.cfg.OpenBrowser(authURL)
		}
	})
	if err != nil {
		return nil, err
	}
	tok, err := cfg.Exchange(s.httpContext(ctx), code, oauth2.VerifierOption(verifier), resourceParam)
	if err != nil {
		return nil, fmt.Errorf("exchanging authorization code: %w", err)
	}
	return tok, nil
}

func waitForCode(ctx context.Context, listener net.Listener, state string, open func()) (string, error) {
	codes := make(chan string, 1)
	failures := make(chan error, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		query := r.URL.Query()
		if query.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		if reason := query.Get("error"); reason != "" {
			fmt.Fprintf(w, "Sign-in failed: %s. You can close this window.", reason)
			failures <- fmt.Errorf("authorization failed: %s %s", reason, query.Get("error_description"))
			return
		}
		fmt.Fprint(w, "Signed in. You can close this window and return to your MCP client.")
		codes <- query.Get("code")
	})}
	go server.Serve(listener)
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()

	open()
	select {
	case code := <-codes:
		return code, nil
	case err := <-failures:
		return "", err
	case <-time.After(5 * time.Minute):
		return "", errors.New("timed out waiting for browser sign-in")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func loopbackPort(redirectURI string) int {
	_, rest, ok := strings.Cut(redirectURI, "://127.0.0.1:")
	if !ok {
		return 0
	}
	var port int
	fmt.Sscanf(rest, "%d", &port)
	return port
}
