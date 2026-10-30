package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/knwoop/iap-mcp-proxy/internal/signin"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const keyringService = "iap-mcp-proxy"

// oauthSource implements the installed-app (desktop) OAuth 2.0 flow
// against Google. The first run opens a browser to obtain a refresh
// token, which is persisted (keychain, falling back to a 0600 file).
// Subsequent runs silently exchange the refresh token for ID tokens.
//
// IAP programmatic access requires the OAuth client to live in the same
// project as the IAP resource; see
// https://cloud.google.com/iap/docs/authentication-howto
type oauthSource struct {
	cfg    *oauth2.Config
	signIn signin.Interaction
	log    *slog.Logger
}

func newOAuthSource(ctx context.Context, c Config) (Source, error) {
	if c.OAuthClientID == "" || c.OAuthClientSecret == "" {
		return nil, errors.New("--credentials=oauth requires IAP_MCP_OAUTH_CLIENT_ID and IAP_MCP_OAUTH_CLIENT_SECRET (a desktop OAuth client in the same project as the IAP resource; see https://cloud.google.com/iap/docs/authentication-howto)")
	}
	log := c.Logger
	if log == nil {
		log = slog.Default()
	}
	return &oauthSource{
		cfg: &oauth2.Config{
			ClientID:     c.OAuthClientID,
			ClientSecret: c.OAuthClientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email"},
		},
		signIn: c.SignIn,
		log:    log,
	}, nil
}

func (s *oauthSource) Token(ctx context.Context) (string, error) {
	rt, err := s.loadRefreshToken()
	if err == nil && rt != "" {
		if id, err := s.idTokenFromRefresh(ctx, rt); err == nil {
			return id, nil
		} else {
			s.log.Warn("stored refresh token rejected; re-running browser sign-in", "error", err)
		}
	}

	rt, id, err := s.browserFlow(ctx)
	if err != nil {
		return "", err
	}
	if err := s.storeRefreshToken(rt); err != nil {
		s.log.Warn("could not persist refresh token; you will be asked to sign in again next run", "error", err)
	}
	return id, nil
}

// idTokenFromRefresh exchanges a stored refresh token for a fresh ID token.
func (s *oauthSource) idTokenFromRefresh(ctx context.Context, refreshToken string) (string, error) {
	tok, err := s.cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return "", fmt.Errorf("refreshing token: %w", err)
	}
	id, _ := tok.Extra("id_token").(string)
	if id == "" {
		return "", errors.New("token response contained no id_token")
	}
	return id, nil
}

// browserFlow runs the interactive installed-app flow: local callback
// listener, browser launch, code exchange (with PKCE).
func (s *oauthSource) browserFlow(ctx context.Context) (refreshToken, idToken string, err error) {
	ctx, cancel := context.WithTimeoutCause(ctx, 5*time.Minute, errors.New("timed out waiting for browser sign-in"))
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", fmt.Errorf("starting OAuth callback listener: %w", err)
	}
	defer ln.Close()

	cfg := *s.cfg
	cfg.RedirectURL = fmt.Sprintf("http://%s/callback", ln.Addr().String())

	state, err := randomState()
	if err != nil {
		return "", "", err
	}
	verifier := oauth2.GenerateVerifier()
	authURL := cfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.S256ChallengeOption(verifier),
		// Force a refresh token even if the user consented before.
		oauth2.SetAuthURLParam("prompt", "consent"),
	)

	s.log.Info("starting Google sign-in", "url", authURL)
	code, err := s.signIn.WaitForCode(ctx, ln, authURL, state, "Google for IAP")
	if err != nil {
		return "", "", err
	}

	tok, err := cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return "", "", fmt.Errorf("exchanging authorization code: %w", err)
	}
	id, _ := tok.Extra("id_token").(string)
	if id == "" {
		return "", "", errors.New("token response contained no id_token")
	}
	if tok.RefreshToken == "" {
		return "", "", errors.New("token response contained no refresh token")
	}
	return tok.RefreshToken, id, nil
}

func randomState() (string, error) {
	tok, err := generateRandomToken()
	if err != nil {
		return "", fmt.Errorf("generating OAuth state: %w", err)
	}
	return tok, nil
}

// --- refresh token persistence ---

func (s *oauthSource) keyringKey() string { return "refresh-token:" + s.cfg.ClientID }

func (s *oauthSource) loadRefreshToken() (string, error) {
	if v, err := keyring.Get(keyringService, s.keyringKey()); err == nil {
		return v, nil
	}
	b, err := os.ReadFile(s.fallbackPath())
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (s *oauthSource) storeRefreshToken(rt string) error {
	if err := keyring.Set(keyringService, s.keyringKey(), rt); err == nil {
		return nil
	} else {
		s.log.Warn("OS keychain unavailable; storing refresh token in a 0600 file instead", "path", s.fallbackPath(), "keychain_error", err)
	}
	p := s.fallbackPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(rt), 0o600)
}

func (s *oauthSource) fallbackPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "iap-mcp-proxy", "refresh-token-"+s.cfg.ClientID)
}
