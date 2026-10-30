package upstream

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/knwoop/iap-mcp-proxy/internal/iap"
)

// Transport attaches the upstream application's OAuth access token as
// Authorization, on top of Base, which handles IAP. When the
// application rejects the token with its own Bearer challenge, it
// refreshes the token (or signs in again) and retries once.
type Transport struct {
	Base    http.RoundTripper
	Session *Session
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading request body: %w", err)
		}
	}

	resp, err := t.send(req, body)
	if err != nil || !iap.IsApplicationChallenge(resp) {
		return resp, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	t.Session.Invalidate()
	return t.send(req, body)
}

func (t *Transport) send(req *http.Request, body []byte) (*http.Response, error) {
	token, err := t.Session.Token(req.Context())
	if err != nil {
		return nil, fmt.Errorf("signing in to the upstream MCP server: %w", err)
	}
	r := req.Clone(req.Context())
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return t.Base.RoundTrip(r)
}
