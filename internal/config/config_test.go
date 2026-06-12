package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "age1f4hsld4d0jc9x30suxt9fqr3vxd6rjt7eefh4c395taluxfuz5ys2lvg92"

func TestInitAndLoadConfig(t *testing.T) {
	dir := t.TempDir()

	if ProjectInitialized(dir) {
		t.Fatal("fresh temp dir should not be initialized")
	}
	if err := InitConfig(dir, "owner@example.com", testKey); err != nil {
		t.Fatalf("InitConfig: %v", err)
	}
	if !ProjectInitialized(dir) {
		t.Fatal("ProjectInitialized should be true after InitConfig")
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Version != schemaVersion {
		t.Errorf("Version = %q, want %q", cfg.Version, schemaVersion)
	}
	if cfg.ProjectName != filepath.Base(dir) {
		t.Errorf("ProjectName = %q, want %q", cfg.ProjectName, filepath.Base(dir))
	}
	if len(cfg.Recipients) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(cfg.Recipients))
	}
	r := cfg.Recipients[0]
	if r.Email != "owner@example.com" || r.PublicKey != testKey {
		t.Errorf("unexpected recipient: %+v", r)
	}
	if r.AddedBy != "owner@example.com" {
		t.Errorf("AddedBy = %q, want self", r.AddedBy)
	}
	if r.AddedOn == nil {
		t.Error("AddedOn should be set on init")
	}
}

func TestLoadConfigMissing(t *testing.T) {
	if _, err := LoadConfig(t.TempDir()); err == nil {
		t.Fatal("LoadConfig on uninitialized dir should fail")
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	envlockDir := filepath.Join(dir, envlockDirName)
	if err := os.MkdirAll(envlockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(envlockDir, configFileName), []byte("{not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(dir); err == nil {
		t.Fatal("LoadConfig with invalid YAML should fail")
	}
}

func TestAddRecipient(t *testing.T) {
	cfg := &Config{Version: schemaVersion}

	if err := AddRecipient(cfg, "alice@example.com", testKey, "owner@example.com"); err != nil {
		t.Fatalf("AddRecipient: %v", err)
	}
	if len(cfg.Recipients) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(cfg.Recipients))
	}
	if cfg.Recipients[0].AddedBy != "owner@example.com" {
		t.Errorf("AddedBy = %q", cfg.Recipients[0].AddedBy)
	}

	// Duplicate email must be rejected.
	err := AddRecipient(cfg, "alice@example.com", testKey, "owner@example.com")
	if err == nil {
		t.Fatal("duplicate AddRecipient should fail")
	}
	if !strings.Contains(err.Error(), "already has access") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRemoveRecipient(t *testing.T) {
	cfg := &Config{}
	for _, email := range []string{"a@x.com", "b@x.com", "c@x.com"} {
		if err := AddRecipient(cfg, email, testKey, "a@x.com"); err != nil {
			t.Fatal(err)
		}
	}

	if err := RemoveRecipient(cfg, "b@x.com"); err != nil {
		t.Fatalf("RemoveRecipient: %v", err)
	}
	if len(cfg.Recipients) != 2 {
		t.Fatalf("expected 2 recipients, got %d", len(cfg.Recipients))
	}
	for _, r := range cfg.Recipients {
		if r.Email == "b@x.com" {
			t.Error("b@x.com should have been removed")
		}
	}

	if err := RemoveRecipient(cfg, "nobody@x.com"); err == nil {
		t.Fatal("removing unknown recipient should fail")
	}
}

func TestSaveAndReloadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := InitConfig(dir, "owner@example.com", testKey); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddRecipient(cfg, "alice@example.com", testKey, "owner@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(dir, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	reloaded, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Recipients) != 2 {
		t.Fatalf("expected 2 recipients after reload, got %d", len(reloaded.Recipients))
	}
}

func TestGetRecipientPublicKeys(t *testing.T) {
	cfg := &Config{Recipients: []Recipient{
		{Email: "a@x.com", PublicKey: "key-a"},
		{Email: "b@x.com", PublicKey: "key-b"},
	}}
	keys := GetRecipientPublicKeys(cfg)
	if len(keys) != 2 || keys[0] != "key-a" || keys[1] != "key-b" {
		t.Errorf("GetRecipientPublicKeys = %v", keys)
	}
}
