package gitignore_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tunahandogan/envlock/internal/gitignore"
)

func TestEnsureEntries_CreatesFile(t *testing.T) {
	dir := t.TempDir()

	added, err := gitignore.EnsureEntries(dir, []string{".env", ".env.*"})
	if err != nil {
		t.Fatalf("EnsureEntries: %v", err)
	}
	if len(added) != 2 {
		t.Errorf("added: got %d, want 2", len(added))
	}

	data, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf("reading .gitignore: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, ".env") {
		t.Error(".gitignore missing .env")
	}
	if !strings.Contains(content, ".env.*") {
		t.Error(".gitignore missing .env.*")
	}
}

func TestEnsureEntries_AppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(path, []byte("*.log\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	added, err := gitignore.EnsureEntries(dir, []string{".env"})
	if err != nil {
		t.Fatalf("EnsureEntries: %v", err)
	}
	if len(added) != 1 {
		t.Errorf("added: got %d, want 1", len(added))
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, "*.log") {
		t.Error("existing entry *.log was removed")
	}
	if !strings.Contains(content, ".env") {
		t.Error(".env not appended")
	}
}

func TestEnsureEntries_SkipsDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(path, []byte(".env\n.env.*\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	added, err := gitignore.EnsureEntries(dir, []string{".env", ".env.*"})
	if err != nil {
		t.Fatalf("EnsureEntries: %v", err)
	}
	if len(added) != 0 {
		t.Errorf("expected 0 additions, got %d: %v", len(added), added)
	}

	// File should be unchanged.
	data, _ := os.ReadFile(path)
	if string(data) != ".env\n.env.*\n" {
		t.Errorf("file was modified when no changes were needed: %q", string(data))
	}
}

func TestEnsureEntries_PartialDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(path, []byte(".env\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	added, err := gitignore.EnsureEntries(dir, []string{".env", ".env.*", "!.env.example"})
	if err != nil {
		t.Fatalf("EnsureEntries: %v", err)
	}
	if len(added) != 2 {
		t.Errorf("added: got %d, want 2", len(added))
	}

	data, _ := os.ReadFile(path)
	content := string(data)
	if !strings.Contains(content, ".env.*") {
		t.Error(".env.* not added")
	}
	if !strings.Contains(content, "!.env.example") {
		t.Error("!.env.example not added")
	}
}
