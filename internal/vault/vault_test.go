package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/tunahandogan/envlock/internal/crypto"
	"github.com/tunahandogan/envlock/internal/vault"
)

// newIdentity generates a fresh age X25519 keypair for use in a single test.
func newIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generating test identity: %v", err)
	}
	return id
}

// envlockDir creates a .envlock subdirectory inside dir and returns dir.
func envlockDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".envlock"), 0o700); err != nil {
		t.Fatalf("creating .envlock dir: %v", err)
	}
	return dir
}

// ── Crypto roundtrip ──────────────────────────────────────────────────────────

func TestEncryptDecryptRoundtrip(t *testing.T) {
	id := newIdentity(t)
	want := []byte("hello, envlock")

	ciphertext, err := crypto.Encrypt(want, []age.Recipient{id.Recipient()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := crypto.Decrypt(ciphertext, id)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("roundtrip: got %q, want %q", got, want)
	}
}

func TestMultiRecipient(t *testing.T) {
	const n = 3
	ids := make([]*age.X25519Identity, n)
	recipients := make([]age.Recipient, n)
	for i := range ids {
		ids[i] = newIdentity(t)
		recipients[i] = ids[i].Recipient()
	}

	want := []byte("multi-recipient payload")
	ciphertext, err := crypto.Encrypt(want, recipients)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	for i, id := range ids {
		got, err := crypto.Decrypt(ciphertext, id)
		if err != nil {
			t.Errorf("recipient %d could not decrypt: %v", i, err)
			continue
		}
		if string(got) != string(want) {
			t.Errorf("recipient %d: got %q, want %q", i, got, want)
		}
	}
}

func TestDecryptWrongKey(t *testing.T) {
	encryptor := newIdentity(t)
	outsider := newIdentity(t)

	ciphertext, err := crypto.Encrypt([]byte("secret"), []age.Recipient{encryptor.Recipient()})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = crypto.Decrypt(ciphertext, outsider)
	if err == nil {
		t.Error("expected error when decrypting with an unrelated key, got nil")
	}
}

func TestDecryptCorrupted(t *testing.T) {
	id := newIdentity(t)
	_, err := crypto.Decrypt([]byte("this is not valid age ciphertext"), id)
	if err == nil {
		t.Error("expected error on corrupted ciphertext, got nil")
	}
}

func TestParseRecipientAndIdentity(t *testing.T) {
	id := newIdentity(t)

	recipient, err := crypto.ParseRecipient(id.Recipient().String())
	if err != nil {
		t.Fatalf("ParseRecipient: %v", err)
	}
	identity, err := crypto.ParseIdentity(id.String())
	if err != nil {
		t.Fatalf("ParseIdentity: %v", err)
	}

	want := []byte("parse roundtrip")
	ct, err := crypto.Encrypt(want, []age.Recipient{recipient})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := crypto.Decrypt(ct, identity)
	if err != nil {
		t.Fatalf("Decrypt after parse: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ── Vault struct ──────────────────────────────────────────────────────────────

func TestVaultSetGetDelete(t *testing.T) {
	v := vault.NewVault()
	v.Set("DB_URL", "postgres://localhost/test")
	v.Set("API_KEY", "s3cr3t")

	if val, ok := v.Get("DB_URL"); !ok || val != "postgres://localhost/test" {
		t.Errorf("Get DB_URL: got (%q, %v), want (%q, true)", val, ok, "postgres://localhost/test")
	}
	if _, ok := v.Get("MISSING"); ok {
		t.Error("Get MISSING: expected false, got true")
	}

	v.Delete("API_KEY")
	if _, ok := v.Get("API_KEY"); ok {
		t.Error("API_KEY still present after Delete")
	}
}

func TestVaultList(t *testing.T) {
	v := vault.NewVault()
	v.Set("ZEBRA", "1")
	v.Set("APPLE", "2")
	v.Set("MANGO", "3")

	keys := v.List()
	want := []string{"APPLE", "MANGO", "ZEBRA"}
	if len(keys) != len(want) {
		t.Fatalf("List len: got %d, want %d", len(keys), len(want))
	}
	for i, k := range keys {
		if k != want[i] {
			t.Errorf("List[%d]: got %q, want %q", i, k, want[i])
		}
	}
}

func TestVaultMetadataVersioning(t *testing.T) {
	v := vault.NewVault()
	if v.Metadata.Version != 1 {
		t.Errorf("initial Version: got %d, want 1", v.Metadata.Version)
	}
	v.Set("K", "v")
	if v.Metadata.Version != 2 {
		t.Errorf("after Set, Version: got %d, want 2", v.Metadata.Version)
	}
	v.Delete("K")
	if v.Metadata.Version != 3 {
		t.Errorf("after Delete, Version: got %d, want 3", v.Metadata.Version)
	}
}

func TestVaultToFromJSON(t *testing.T) {
	v := vault.NewVault()
	v.Set("KEY", "value")

	data, err := v.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	v2, err := vault.VaultFromJSON(data)
	if err != nil {
		t.Fatalf("VaultFromJSON: %v", err)
	}
	if val, ok := v2.Get("KEY"); !ok || val != "value" {
		t.Errorf("KEY after JSON roundtrip: got (%q, %v)", val, ok)
	}
}

// ── Storage (save / load) ─────────────────────────────────────────────────────

func TestSaveLoadVault(t *testing.T) {
	id := newIdentity(t)
	dir := envlockDir(t)

	v := vault.NewVault()
	v.Set("HOST", "localhost")
	v.Set("PORT", "5432")

	if err := vault.SaveVault(dir, v, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatalf("SaveVault: %v", err)
	}

	loaded, err := vault.LoadVault(dir, id)
	if err != nil {
		t.Fatalf("LoadVault: %v", err)
	}
	for _, tc := range []struct{ key, want string }{
		{"HOST", "localhost"},
		{"PORT", "5432"},
	} {
		if got, ok := loaded.Get(tc.key); !ok || got != tc.want {
			t.Errorf("Get %s: got (%q, %v), want (%q, true)", tc.key, got, ok, tc.want)
		}
	}
}

func TestLoadVaultNotExist(t *testing.T) {
	id := newIdentity(t)
	dir := envlockDir(t)

	// No vault.age present — LoadVault should return an empty vault, not an error.
	v, err := vault.LoadVault(dir, id)
	if err != nil {
		t.Fatalf("LoadVault on missing file: %v", err)
	}
	if len(v.Secrets) != 0 {
		t.Errorf("expected empty vault, got %d secrets", len(v.Secrets))
	}
}

func TestLoadVaultCorrupted(t *testing.T) {
	id := newIdentity(t)
	dir := envlockDir(t)

	// Write garbage to simulate a corrupted vault file.
	vaultPath := filepath.Join(dir, ".envlock", "vault.age")
	if err := os.WriteFile(vaultPath, []byte("not valid age ciphertext"), 0o644); err != nil {
		t.Fatalf("writing corrupted vault: %v", err)
	}

	_, err := vault.LoadVault(dir, id)
	if err == nil {
		t.Error("expected error loading corrupted vault, got nil")
	}
}

func TestSaveLoadEmptyVault(t *testing.T) {
	id := newIdentity(t)
	dir := envlockDir(t)

	v := vault.NewVault()
	if err := vault.SaveVault(dir, v, []age.Recipient{id.Recipient()}); err != nil {
		t.Fatalf("SaveVault empty: %v", err)
	}
	loaded, err := vault.LoadVault(dir, id)
	if err != nil {
		t.Fatalf("LoadVault empty: %v", err)
	}
	if len(loaded.Secrets) != 0 {
		t.Errorf("expected 0 secrets, got %d", len(loaded.Secrets))
	}
}

func TestSaveLoadMultiRecipientVault(t *testing.T) {
	const n = 3
	ids := make([]*age.X25519Identity, n)
	recipients := make([]age.Recipient, n)
	for i := range ids {
		ids[i] = newIdentity(t)
		recipients[i] = ids[i].Recipient()
	}

	dir := envlockDir(t)
	v := vault.NewVault()
	v.Set("SHARED_SECRET", "topsecret")

	if err := vault.SaveVault(dir, v, recipients); err != nil {
		t.Fatalf("SaveVault: %v", err)
	}

	for i, id := range ids {
		loaded, err := vault.LoadVault(dir, id)
		if err != nil {
			t.Errorf("recipient %d could not load vault: %v", i, err)
			continue
		}
		if val, ok := loaded.Get("SHARED_SECRET"); !ok || val != "topsecret" {
			t.Errorf("recipient %d: SHARED_SECRET got (%q, %v)", i, val, ok)
		}
	}
}

func TestLoadVaultWrongKey(t *testing.T) {
	encryptor := newIdentity(t)
	outsider := newIdentity(t)
	dir := envlockDir(t)

	v := vault.NewVault()
	v.Set("K", "v")
	if err := vault.SaveVault(dir, v, []age.Recipient{encryptor.Recipient()}); err != nil {
		t.Fatalf("SaveVault: %v", err)
	}

	_, err := vault.LoadVault(dir, outsider)
	if err == nil {
		t.Error("expected error loading vault with unrelated key, got nil")
	}
}
