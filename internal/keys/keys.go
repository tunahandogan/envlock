// Package keys handles age keypair generation, persistence, and lookup.
// Private keys are stored under ~/.envlock/keys/<email>.key with mode 0600.
package keys

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

const (
	envlockDir   = ".envlock"
	keySubdir    = "keys"
	keyExt       = ".key"
	keysDirPerms = 0o700
	keyFilePerms = 0o600
)

// GenerateKeypair generates a new age X25519 keypair.
func GenerateKeypair() (*age.X25519Identity, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generating age identity: %w", err)
	}
	return identity, nil
}

// SavePrivateKey writes identity to ~/.envlock/keys/<email>.key with mode 0600.
// It creates parent directories as needed and returns the absolute path of the saved file.
func SavePrivateKey(identity *age.X25519Identity, email string) (string, error) {
	dir, err := keysDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, keysDirPerms); err != nil {
		return "", fmt.Errorf("creating keys directory %s: %w", dir, err)
	}

	keyPath := filepath.Join(dir, email+keyExt)
	content := "# age private key managed by envlock\n" +
		"# email: " + email + "\n" +
		identity.String() + "\n"

	if err := os.WriteFile(keyPath, []byte(content), keyFilePerms); err != nil {
		return "", fmt.Errorf("writing private key to %s: %w", keyPath, err)
	}
	return keyPath, nil
}

// LoadPrivateKey reads and parses the private key for email from ~/.envlock/keys/<email>.key.
// Comment lines (starting with #) and blank lines in the key file are ignored.
func LoadPrivateKey(email string) (*age.X25519Identity, error) {
	dir, err := keysDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, email+keyExt)

	f, err := os.Open(keyPath)
	if err != nil {
		return nil, fmt.Errorf("opening private key %s: %w", keyPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		identity, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, fmt.Errorf("parsing private key in %s: %w", keyPath, err)
		}
		return identity, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading private key %s: %w", keyPath, err)
	}
	return nil, fmt.Errorf("no valid age private key found in %s", keyPath)
}

// PublicKeyString returns the bech32-encoded public key string (age1...) for identity.
func PublicKeyString(identity *age.X25519Identity) string {
	return identity.Recipient().String()
}

// KeyExists reports whether a private key file for email already exists.
func KeyExists(email string) (bool, error) {
	dir, err := keysDir()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(filepath.Join(dir, email+keyExt))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("checking key file for %s: %w", email, err)
	}
	return true, nil
}

// KeyPath returns the absolute path to the private key file for email.
func KeyPath(email string) (string, error) {
	dir, err := keysDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, email+keyExt), nil
}

// keysDir returns the absolute path to the user's envlock keys directory.
func keysDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	return filepath.Join(home, envlockDir, keySubdir), nil
}
