package keys

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// setTempHome points the user's home directory at a temp dir so key files
// never touch the real ~/.envlock.
func setTempHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	return home
}

func TestGenerateKeypair(t *testing.T) {
	id, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if !strings.HasPrefix(id.String(), "AGE-SECRET-KEY-1") {
		t.Errorf("private key has unexpected format: %q", id.String()[:20])
	}
	if !strings.HasPrefix(PublicKeyString(id), "age1") {
		t.Errorf("public key has unexpected format: %q", PublicKeyString(id))
	}
}

func TestSaveAndLoadPrivateKey(t *testing.T) {
	home := setTempHome(t)
	id, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	path, err := SavePrivateKey(id, "user@example.com")
	if err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	want := filepath.Join(home, ".envlock", "keys", "user@example.com.key")
	if path != want {
		t.Errorf("key path = %q, want %q", path, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadPrivateKey("user@example.com")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if loaded.String() != id.String() {
		t.Error("loaded key does not match saved key")
	}
}

func TestLoadPrivateKeySkipsComments(t *testing.T) {
	setTempHome(t)
	id, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	path, err := SavePrivateKey(id, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "#") {
		t.Fatal("saved key file should start with a comment header")
	}

	loaded, err := LoadPrivateKey("user@example.com")
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if loaded.String() != id.String() {
		t.Error("comments in key file broke parsing")
	}
}

func TestLoadPrivateKeyMissing(t *testing.T) {
	setTempHome(t)
	if _, err := LoadPrivateKey("nobody@example.com"); err == nil {
		t.Fatal("loading a missing key should fail")
	}
}

func TestLoadPrivateKeyInvalidContent(t *testing.T) {
	home := setTempHome(t)
	dir := filepath.Join(home, ".envlock", "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad@example.com.key"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey("bad@example.com"); err == nil {
		t.Fatal("loading an invalid key file should fail")
	}
}

func TestKeyExists(t *testing.T) {
	setTempHome(t)

	ok, err := KeyExists("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("KeyExists should be false before saving")
	}

	id, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SavePrivateKey(id, "user@example.com"); err != nil {
		t.Fatal(err)
	}

	ok, err = KeyExists("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("KeyExists should be true after saving")
	}
}

func TestKeyPath(t *testing.T) {
	home := setTempHome(t)
	path, err := KeyPath("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".envlock", "keys", "user@example.com.key")
	if path != want {
		t.Errorf("KeyPath = %q, want %q", path, want)
	}
}
