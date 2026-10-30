package signin

import (
	"errors"
	"net"
	"testing"
)

func listen(t *testing.T) net.Listener {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func TestTakesTheCodeFromThePastedRedirect(t *testing.T) {
	pasted := make(chan string, 3)
	pasted <- "not an address"
	pasted <- "http://127.0.0.1:1/callback?code=stolen&state=another-sign-in"
	pasted <- "  http://127.0.0.1:1/callback?code=code-1&state=state-1  "

	code, err := Interaction{Pasted: pasted}.WaitForCode(t.Context(), listen(t), "https://as.example.com/authorize", "state-1", "the server")

	if err != nil || code != "code-1" {
		t.Fatalf("code = %q, %v; want code-1 from the redirect of this sign-in", code, err)
	}
}

func TestFailsWithoutABrowserOrATerminal(t *testing.T) {
	if _, err := (Interaction{}).WaitForCode(t.Context(), listen(t), "https://as.example.com/authorize", "state-1", "the server"); !errors.Is(err, ErrNoBrowser) {
		t.Errorf("without a browser or a terminal: %v, want ErrNoBrowser", err)
	}

	closed := make(chan string)
	close(closed)
	if _, err := (Interaction{Pasted: closed}).WaitForCode(t.Context(), listen(t), "https://as.example.com/authorize", "state-1", "the server"); !errors.Is(err, ErrNoBrowser) {
		t.Errorf("with a closed terminal: %v, want ErrNoBrowser", err)
	}
}
