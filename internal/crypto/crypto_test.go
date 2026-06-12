package crypto

import (
	"strings"
	"testing"

	"filippo.io/age"
)

func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	return id
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	id := newIdentity(t)
	plaintext := []byte("DATABASE_URL=postgres://localhost/mydb")

	ciphertext, err := Encrypt(plaintext, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if !strings.HasPrefix(string(ciphertext), "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Errorf("ciphertext is not PEM-armored: %q", ciphertext[:40])
	}

	got, err := Decrypt(ciphertext, id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptWithAnyRecipientKey(t *testing.T) {
	alice := newIdentity(t)
	bob := newIdentity(t)
	plaintext := []byte("shared secret")

	ciphertext, err := Encrypt(plaintext, []age.Recipient{alice.Recipient(), bob.Recipient()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	for name, id := range map[string]age.Identity{"alice": alice, "bob": bob} {
		got, err := Decrypt(ciphertext, id)
		if err != nil {
			t.Errorf("%s should be able to decrypt: %v", name, err)
			continue
		}
		if string(got) != string(plaintext) {
			t.Errorf("%s: got %q, want %q", name, got, plaintext)
		}
	}
}

func TestDecryptWithWrongKeyFails(t *testing.T) {
	owner := newIdentity(t)
	intruder := newIdentity(t)

	ciphertext, err := Encrypt([]byte("secret"), []age.Recipient{owner.Recipient()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := Decrypt(ciphertext, intruder); err == nil {
		t.Fatal("Decrypt with non-recipient key should fail")
	}
}

func TestDecryptGarbageFails(t *testing.T) {
	id := newIdentity(t)
	if _, err := Decrypt([]byte("not age ciphertext"), id); err == nil {
		t.Fatal("Decrypt of garbage input should fail")
	}
}

func TestEncryptEmptyPlaintext(t *testing.T) {
	id := newIdentity(t)
	ciphertext, err := Encrypt(nil, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(ciphertext, id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %q", got)
	}
}

func TestParseRecipient(t *testing.T) {
	id := newIdentity(t)

	if _, err := ParseRecipient(id.Recipient().String()); err != nil {
		t.Errorf("ParseRecipient with valid key: %v", err)
	}
	if _, err := ParseRecipient("age1invalid"); err == nil {
		t.Error("ParseRecipient with invalid key should fail")
	}
	if _, err := ParseRecipient(""); err == nil {
		t.Error("ParseRecipient with empty string should fail")
	}
}

func TestParseIdentity(t *testing.T) {
	id := newIdentity(t)

	parsed, err := ParseIdentity(id.String())
	if err != nil {
		t.Fatalf("ParseIdentity with valid key: %v", err)
	}
	x25519, ok := parsed.(*age.X25519Identity)
	if !ok {
		t.Fatalf("ParseIdentity returned %T, want *age.X25519Identity", parsed)
	}
	if x25519.Recipient().String() != id.Recipient().String() {
		t.Error("parsed identity does not match original public key")
	}
	if _, err := ParseIdentity("AGE-SECRET-KEY-INVALID"); err == nil {
		t.Error("ParseIdentity with invalid key should fail")
	}
}
