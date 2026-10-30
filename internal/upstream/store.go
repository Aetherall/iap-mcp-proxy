package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/zalando/go-keyring"
)

const keyringService = "iap-mcp-proxy"

// useKeychain is turned off by tests, so they keep to the file under
// their own config dir instead of the developer's OS keychain.
var useKeychain = true

// store persists one resource's credentials in the OS keychain, falling
// back to a 0600 file when no keychain is available.
type store struct {
	key      string
	path     string
	keychain bool
	log      *slog.Logger
}

func newStore(resource string, log *slog.Logger) *store {
	sum := sha256.Sum256([]byte(resource))
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return &store{
		key:      "upstream-oauth:" + resource,
		path:     filepath.Join(dir, "iap-mcp-proxy", "upstream-oauth-"+hex.EncodeToString(sum[:8])+".json"),
		keychain: useKeychain,
		log:      log,
	}
}

func (s *store) load() *storedState {
	raw, err := s.keychainGet()
	if err != nil {
		data, fileErr := os.ReadFile(s.path)
		if fileErr != nil {
			return nil
		}
		raw = string(data)
	}
	var state storedState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		s.log.Warn("ignoring unreadable stored upstream OAuth credentials", "error", err)
		return nil
	}
	return &state
}

func (s *store) save(state *storedState) {
	data, err := json.Marshal(state)
	if err != nil {
		s.log.Warn("could not encode upstream OAuth credentials", "error", err)
		return
	}
	if s.keychain {
		if err := keyring.Set(keyringService, s.key, string(data)); err == nil {
			return
		} else {
			s.log.Warn("OS keychain unavailable; storing upstream OAuth credentials in a 0600 file instead", "path", s.path, "keychain_error", err)
		}
		// load prefers the keychain; drop any older entry there so it
		// does not shadow the file.
		_ = keyring.Delete(keyringService, s.key)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		s.log.Warn("could not store upstream OAuth credentials; you will be asked to sign in again next run", "error", err)
		return
	}
	if err := os.WriteFile(s.path, data, 0o600); err != nil {
		s.log.Warn("could not store upstream OAuth credentials; you will be asked to sign in again next run", "error", err)
	}
}

func (s *store) keychainGet() (string, error) {
	if !s.keychain {
		return "", keyring.ErrNotFound
	}
	return keyring.Get(keyringService, s.key)
}

func (s *store) delete() error {
	var keyErr error
	if s.keychain {
		keyErr = keyring.Delete(keyringService, s.key)
	}
	if errors.Is(keyErr, keyring.ErrNotFound) {
		keyErr = nil
	}
	fileErr := os.Remove(s.path)
	if errors.Is(fileErr, fs.ErrNotExist) {
		fileErr = nil
	}
	return errors.Join(keyErr, fileErr)
}
