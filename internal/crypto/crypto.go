// Package crypto wraps filippo.io/age to provide armored multi-recipient
// encryption and decryption primitives used by the vault layer.
package crypto

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// Encrypt encrypts data for all recipients using age and returns PEM-armored
// ciphertext. The armored format is text-safe and suitable for git diffs.
func Encrypt(data []byte, recipients []age.Recipient) ([]byte, error) {
	var buf bytes.Buffer

	armorW := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorW, recipients...)
	if err != nil {
		return nil, fmt.Errorf("initialising age encryption: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("writing plaintext to age stream: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing age writer: %w", err)
	}
	if err := armorW.Close(); err != nil {
		return nil, fmt.Errorf("closing armor writer: %w", err)
	}
	return buf.Bytes(), nil
}

// Decrypt decrypts armored age ciphertext using identity.
// Returns a user-facing "not authorised" error if the key does not match,
// deliberately avoiding internal crypto details in the message.
func Decrypt(data []byte, identity age.Identity) ([]byte, error) {
	armorR := armor.NewReader(bytes.NewReader(data))
	r, err := age.Decrypt(armorR, identity)
	if err != nil {
		return nil, fmt.Errorf("the provided key is not authorised for this vault")
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted stream: %w", err)
	}
	return plaintext, nil
}

// ParseRecipient parses a bech32-encoded age public key (age1…) into an age.Recipient.
func ParseRecipient(publicKey string) (age.Recipient, error) {
	r, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, fmt.Errorf("parsing recipient public key: %w", err)
	}
	return r, nil
}

// ParseIdentity parses an age private key string (AGE-SECRET-KEY-1…) into an age.Identity.
func ParseIdentity(privateKey string) (age.Identity, error) {
	id, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	return id, nil
}
