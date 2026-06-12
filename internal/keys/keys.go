// Package keys handles age keypair generation, persistence, and lookup.
// Private keys are stored under ~/.envlock/keys/<email>.key with mode 0600,
// either as a plain age key or — when a passphrase is set — as an
// age-scrypt-encrypted, PEM-armored blob.
package keys

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	envlockDir   = ".envlock"
	keySubdir    = "keys"
	keyExt       = ".key"
	keysDirPerms = 0o700
	keyFilePerms = 0o600

	armorHeader = "-----BEGIN AGE ENCRYPTED FILE-----"
)

// PassphrasePrompt is called when LoadPrivateKey encounters a
// passphrase-protected key file. The CLI layer installs an interactive
// terminal prompt; tests may inject a fixed value. If nil, loading an
// encrypted key fails with an actionable error.
var PassphrasePrompt func(email string) (string, error)

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
	return SavePrivateKeyWithPassphrase(identity, email, "")
}

// SavePrivateKeyWithPassphrase writes identity to ~/.envlock/keys/<email>.key.
// With an empty passphrase the key is stored in plain text (mode 0600); with a
// passphrase it is encrypted using age's scrypt recipient so the file is
// useless without the passphrase.
func SavePrivateKeyWithPassphrase(identity *age.X25519Identity, email, passphrase string) (string, error) {
	dir, err := keysDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, keysDirPerms); err != nil {
		return "", fmt.Errorf("creating keys directory %s: %w", dir, err)
	}

	body := identity.String()
	if passphrase != "" {
		encrypted, err := encryptWithPassphrase(body, passphrase)
		if err != nil {
			return "", err
		}
		body = encrypted
	}

	keyPath := filepath.Join(dir, email+keyExt)
	content := "# age private key managed by envlock\n" +
		"# email: " + email + "\n" +
		body + "\n"

	if err := os.WriteFile(keyPath, []byte(content), keyFilePerms); err != nil {
		return "", fmt.Errorf("writing private key to %s: %w", keyPath, err)
	}
	return keyPath, nil
}

// LoadPrivateKey reads and parses the private key for email from ~/.envlock/keys/<email>.key.
// Comment lines (starting with #) and blank lines in the key file are ignored.
// Passphrase-protected keys are decrypted via PassphrasePrompt.
func LoadPrivateKey(email string) (*age.X25519Identity, error) {
	dir, err := keysDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, email+keyExt)

	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("opening private key %s: %w", keyPath, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == armorHeader {
			return loadEncryptedKey(data, email, keyPath)
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

// KeyIsEncrypted reports whether the key file for email is passphrase-protected.
func KeyIsEncrypted(email string) (bool, error) {
	dir, err := keysDir()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(filepath.Join(dir, email+keyExt))
	if err != nil {
		return false, fmt.Errorf("reading key file for %s: %w", email, err)
	}
	return bytes.Contains(data, []byte(armorHeader)), nil
}

// loadEncryptedKey prompts for the passphrase and decrypts the armored key blob.
func loadEncryptedKey(data []byte, email, keyPath string) (*age.X25519Identity, error) {
	if PassphrasePrompt == nil {
		return nil, fmt.Errorf("key %s is passphrase-protected but no passphrase prompt is available", keyPath)
	}
	passphrase, err := PassphrasePrompt(email)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}

	// The armor block starts at the header; everything before is comments.
	idx := bytes.Index(data, []byte(armorHeader))
	armored := data[idx:]

	scryptID, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, fmt.Errorf("preparing passphrase identity: %w", err)
	}
	r, err := age.Decrypt(armor.NewReader(bytes.NewReader(armored)), scryptID)
	if err != nil {
		return nil, fmt.Errorf("incorrect passphrase for %s", keyPath)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decrypting key %s: %w", keyPath, err)
	}

	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(plaintext)))
	if err != nil {
		return nil, fmt.Errorf("parsing decrypted key from %s: %w", keyPath, err)
	}
	return identity, nil
}

// encryptWithPassphrase encrypts keyString with an age scrypt recipient and
// returns the PEM-armored ciphertext.
func encryptWithPassphrase(keyString, passphrase string) (string, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", fmt.Errorf("preparing passphrase recipient: %w", err)
	}

	var buf bytes.Buffer
	armorW := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorW, recipient)
	if err != nil {
		return "", fmt.Errorf("encrypting key with passphrase: %w", err)
	}
	if _, err := io.WriteString(w, keyString); err != nil {
		return "", fmt.Errorf("writing key to encryption stream: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalising key encryption: %w", err)
	}
	if err := armorW.Close(); err != nil {
		return "", fmt.Errorf("finalising key armor: %w", err)
	}
	return buf.String(), nil
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
