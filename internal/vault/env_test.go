package vault_test

import (
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/tunahandogan/envlock/internal/vault"
)

func TestVaultFileName(t *testing.T) {
	cases := map[string]string{
		"":           "vault.age",
		"production": "vault.production.age",
		"dev":        "vault.dev.age",
	}
	for env, want := range cases {
		if got := vault.VaultFileName(env); got != want {
			t.Errorf("VaultFileName(%q) = %q, want %q", env, got, want)
		}
	}
}

func TestValidateEnvName(t *testing.T) {
	for _, valid := range []string{"", "production", "dev", "staging-eu", "qa_2"} {
		if err := vault.ValidateEnvName(valid); err != nil {
			t.Errorf("ValidateEnvName(%q) should be valid: %v", valid, err)
		}
	}
	for _, invalid := range []string{"../etc", "pro duction", "a/b", ".hidden", "-lead"} {
		if err := vault.ValidateEnvName(invalid); err == nil {
			t.Errorf("ValidateEnvName(%q) should be rejected", invalid)
		}
	}
}

func TestEnvVaultsAreIsolated(t *testing.T) {
	id := newIdentity(t)
	recipients := []age.Recipient{id.Recipient()}
	dir := envlockDir(t)

	devVault := vault.NewVault()
	devVault.Set("DATABASE_URL", "postgres://localhost/dev")
	if err := vault.SaveVaultEnv(dir, "", devVault, recipients); err != nil {
		t.Fatalf("SaveVaultEnv default: %v", err)
	}

	prodVault := vault.NewVault()
	prodVault.Set("DATABASE_URL", "postgres://prod.example.com/app")
	if err := vault.SaveVaultEnv(dir, "production", prodVault, recipients); err != nil {
		t.Fatalf("SaveVaultEnv production: %v", err)
	}

	// Two distinct files must exist.
	for _, name := range []string{"vault.age", "vault.production.age"} {
		if _, err := os.Stat(filepath.Join(dir, ".envlock", name)); err != nil {
			t.Errorf("expected %s to exist: %v", name, err)
		}
	}

	// Each environment loads its own value.
	gotDev, err := vault.LoadVaultEnv(dir, "", id)
	if err != nil {
		t.Fatalf("LoadVaultEnv default: %v", err)
	}
	if v, _ := gotDev.Get("DATABASE_URL"); v != "postgres://localhost/dev" {
		t.Errorf("default env DATABASE_URL = %q", v)
	}

	gotProd, err := vault.LoadVaultEnv(dir, "production", id)
	if err != nil {
		t.Fatalf("LoadVaultEnv production: %v", err)
	}
	if v, _ := gotProd.Get("DATABASE_URL"); v != "postgres://prod.example.com/app" {
		t.Errorf("production env DATABASE_URL = %q", v)
	}
}

func TestLoadVaultEnvMissingReturnsEmpty(t *testing.T) {
	id := newIdentity(t)
	dir := envlockDir(t)

	v, err := vault.LoadVaultEnv(dir, "staging", id)
	if err != nil {
		t.Fatalf("LoadVaultEnv on missing file: %v", err)
	}
	if len(v.List()) != 0 {
		t.Errorf("expected empty vault, got %d secrets", len(v.List()))
	}
}

func TestListEnvs(t *testing.T) {
	id := newIdentity(t)
	recipients := []age.Recipient{id.Recipient()}
	dir := envlockDir(t)

	envs, err := vault.ListEnvs(dir)
	if err != nil {
		t.Fatalf("ListEnvs on empty project: %v", err)
	}
	if len(envs) != 0 {
		t.Fatalf("expected no envs, got %v", envs)
	}

	for _, env := range []string{"", "production", "staging"} {
		if err := vault.SaveVaultEnv(dir, env, vault.NewVault(), recipients); err != nil {
			t.Fatalf("SaveVaultEnv(%q): %v", env, err)
		}
	}

	envs, err = vault.ListEnvs(dir)
	if err != nil {
		t.Fatalf("ListEnvs: %v", err)
	}
	found := map[string]bool{}
	for _, e := range envs {
		found[e] = true
	}
	for _, want := range []string{"", "production", "staging"} {
		if !found[want] {
			t.Errorf("ListEnvs missing %q (got %v)", want, envs)
		}
	}
	if len(envs) != 3 {
		t.Errorf("expected 3 envs, got %v", envs)
	}
}

func TestSaveVaultEnvRejectsInvalidName(t *testing.T) {
	id := newIdentity(t)
	dir := envlockDir(t)
	err := vault.SaveVaultEnv(dir, "../escape", vault.NewVault(), []age.Recipient{id.Recipient()})
	if err == nil {
		t.Fatal("SaveVaultEnv with path-traversal env name should fail")
	}
}
