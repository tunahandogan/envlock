package keys

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// withPassphrasePrompt installs a fixed passphrase prompt for the test and
// restores the previous prompt afterwards.
func withPassphrasePrompt(t *testing.T, passphrase string, err error) {
	t.Helper()
	prev := PassphrasePrompt
	PassphrasePrompt = func(string) (string, error) { return passphrase, err }
	t.Cleanup(func() { PassphrasePrompt = prev })
}

func TestPassphraseProtectedKeyRoundTrip(t *testing.T) {
	setTempHome(t)
	id, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	path, err := SavePrivateKeyWithPassphrase(id, "user@example.com", "correct horse battery staple")
	if err != nil {
		t.Fatalf("SavePrivateKeyWithPassphrase: %v", err)
	}

	// The key string must not appear in plaintext on disk.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), id.String()) {
		t.Fatal("private key stored in plaintext despite passphrase")
	}
	if !strings.Contains(string(data), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatal("encrypted key file is missing the age armor header")
	}

	encrypted, err := KeyIsEncrypted("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !encrypted {
		t.Error("KeyIsEncrypted should report true")
	}

	withPassphrasePrompt(t, "correct horse battery staple", nil)
	loaded, err := LoadPrivateKey("user@example.com")
	if err != nil {
		t.Fatalf("LoadPrivateKey with correct passphrase: %v", err)
	}
	if loaded.String() != id.String() {
		t.Error("decrypted key does not match original")
	}
}

func TestPassphraseProtectedKeyWrongPassphrase(t *testing.T) {
	setTempHome(t)
	id, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SavePrivateKeyWithPassphrase(id, "user@example.com", "right"); err != nil {
		t.Fatal(err)
	}

	withPassphrasePrompt(t, "wrong", nil)
	if _, err := LoadPrivateKey("user@example.com"); err == nil {
		t.Fatal("LoadPrivateKey with wrong passphrase should fail")
	} else if !strings.Contains(err.Error(), "incorrect passphrase") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestPassphraseProtectedKeyNoPrompt(t *testing.T) {
	setTempHome(t)
	id, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SavePrivateKeyWithPassphrase(id, "user@example.com", "secret"); err != nil {
		t.Fatal(err)
	}

	prev := PassphrasePrompt
	PassphrasePrompt = nil
	t.Cleanup(func() { PassphrasePrompt = prev })

	if _, err := LoadPrivateKey("user@example.com"); err == nil {
		t.Fatal("LoadPrivateKey without a prompt should fail for encrypted keys")
	}
}

func TestPassphrasePromptErrorPropagates(t *testing.T) {
	setTempHome(t)
	id, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SavePrivateKeyWithPassphrase(id, "user@example.com", "secret"); err != nil {
		t.Fatal(err)
	}

	withPassphrasePrompt(t, "", errors.New("user cancelled"))
	if _, err := LoadPrivateKey("user@example.com"); err == nil {
		t.Fatal("prompt error should propagate")
	}
}

func TestEmptyPassphraseStoresPlainKey(t *testing.T) {
	setTempHome(t)
	id, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	path, err := SavePrivateKeyWithPassphrase(id, "user@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), id.String()) {
		t.Fatal("empty passphrase should store the key in plain form")
	}

	encrypted, err := KeyIsEncrypted("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if encrypted {
		t.Error("KeyIsEncrypted should report false for plain keys")
	}
}
