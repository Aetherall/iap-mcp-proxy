// Package signin gets the user through an OAuth authorization code
// sign-in on a loopback redirect: it serves the redirect, sends the
// user to the authorization page, and, for a browser on another
// machine whose redirect cannot reach this one, accepts the redirect
// address pasted back into the terminal.
package signin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ErrNoBrowser is returned when a sign-in is needed but there is no
// browser to open and no terminal to paste the redirect into, as when
// an MCP client runs the proxy on a headless machine.
var ErrNoBrowser = errors.New("sign-in needed but no browser is available; run iap-mcp-proxy --login with the same flags in a terminal")

// Interaction is how the user reaches the authorization page and comes
// back from it.
type Interaction struct {
	// OpenBrowser opens the authorization page; nil when no browser is
	// available.
	OpenBrowser func(url string)
	// Pasted delivers lines the user types in the terminal; nil when
	// there is no terminal to read.
	Pasted <-chan string
}

// Available reports ErrNoBrowser when the user has no way to sign in.
func (i Interaction) Available() error {
	if i.OpenBrowser == nil && i.Pasted == nil {
		return ErrNoBrowser
	}
	return nil
}

// WaitForCode serves the redirect on listener, sends the user to
// authURL to sign in to what, and returns the authorization code from
// the redirect carrying state, whether the browser delivers it or the
// user pastes it.
func (i Interaction) WaitForCode(ctx context.Context, listener net.Listener, authURL, state, what string) (string, error) {
	if err := i.Available(); err != nil {
		return "", err
	}
	type result struct {
		code string
		err  error
	}
	results := make(chan result, 1)
	deliver := func(r result) {
		select {
		case results <- r:
		default:
		}
	}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		code, err := codeFrom(r.URL.Query(), state)
		switch {
		case errors.Is(err, errStateMismatch):
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		case err != nil:
			fmt.Fprintf(w, "Sign-in failed: %v. You can close this window.", err)
		default:
			fmt.Fprint(w, "Signed in. You can close this window and return to your MCP client.")
		}
		deliver(result{code, err})
	})}
	go server.Serve(listener)
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()

	if i.OpenBrowser != nil {
		fmt.Fprintf(os.Stderr, "iap-mcp-proxy: opening browser to sign in to %s.\nIf it does not open, visit:\n%s\n", what, authURL)
		i.OpenBrowser(authURL)
	} else {
		fmt.Fprintf(os.Stderr, "iap-mcp-proxy: to sign in to %s, visit:\n%s\n", what, authURL)
	}
	if i.Pasted != nil {
		fmt.Fprint(os.Stderr, "If your browser is on another machine, it ends on an address that fails to load; paste that address here: ")
	}

	for {
		select {
		case r := <-results:
			return r.code, r.err
		case line, ok := <-i.Pasted:
			if !ok {
				i.Pasted = nil
				if i.OpenBrowser == nil {
					return "", ErrNoBrowser
				}
				continue
			}
			redirect, err := url.Parse(strings.TrimSpace(line))
			if err != nil || redirect.Query().Get("state") == "" {
				fmt.Fprint(os.Stderr, "That is not the address the browser was sent to; paste the whole address: ")
				continue
			}
			code, err := codeFrom(redirect.Query(), state)
			if errors.Is(err, errStateMismatch) {
				fmt.Fprint(os.Stderr, "That address belongs to another sign-in; paste the one from this sign-in: ")
				continue
			}
			return code, err
		case <-ctx.Done():
			return "", context.Cause(ctx)
		}
	}
}

var errStateMismatch = errors.New("state mismatch")

func codeFrom(query url.Values, state string) (string, error) {
	if query.Get("state") != state {
		return "", errStateMismatch
	}
	if reason := query.Get("error"); reason != "" {
		return "", fmt.Errorf("authorization failed: %s %s", reason, query.Get("error_description"))
	}
	if query.Get("code") == "" {
		return "", errors.New("authorization redirect carried no code")
	}
	return query.Get("code"), nil
}

// Lines reads r line by line for Interaction.Pasted. One reader serves
// every sign-in of the process, so none steals another's input.
func Lines(r io.Reader) <-chan string {
	lines := make(chan string)
	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	return lines
}

// HasBrowser guesses whether OpenBrowser can show the user a page: not
// over SSH without a forwarded display, nor on a Unix without one.
func HasBrowser() bool {
	if os.Getenv("SSH_CONNECTION") != "" && os.Getenv("DISPLAY") == "" {
		return false
	}
	switch runtime.GOOS {
	case "darwin", "windows":
		return true
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return false
	}
	_, err := exec.LookPath("xdg-open")
	return err == nil
}

// OpenBrowser opens url in the default browser, best effort.
func OpenBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
