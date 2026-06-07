package env_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/tunahandogan/envlock/internal/env"
)

// parseString is a test helper that parses a raw .env string.
func parseString(t *testing.T, src string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("writing test .env: %v", err)
	}
	m, err := env.ParseEnvFile(path)
	if err != nil {
		t.Fatalf("ParseEnvFile: %v", err)
	}
	return m
}

func TestParseUnquoted(t *testing.T) {
	m := parseString(t, "KEY=value\nFOO=bar\n")
	assertVal(t, m, "KEY", "value")
	assertVal(t, m, "FOO", "bar")
}

func TestParseDoubleQuoted(t *testing.T) {
	m := parseString(t, `KEY="hello world"`)
	assertVal(t, m, "KEY", "hello world")
}

func TestParseSingleQuoted(t *testing.T) {
	m := parseString(t, "KEY='it's a value'")
	// single-quoted stops at the first closing quote
	assertVal(t, m, "KEY", "it")
}

func TestParseEscapeSequences(t *testing.T) {
	m := parseString(t, `KEY="line1\nline2\ttab"`)
	assertVal(t, m, "KEY", "line1\nline2\ttab")
}

func TestParseInlineComment(t *testing.T) {
	m := parseString(t, "KEY=value # comment\n")
	assertVal(t, m, "KEY", "value")
}

func TestParseExportPrefix(t *testing.T) {
	m := parseString(t, "export KEY=value\n")
	assertVal(t, m, "KEY", "value")
}

func TestParseSkipsCommentLines(t *testing.T) {
	m := parseString(t, "# this is a comment\nKEY=value\n")
	if _, ok := m["# this is a comment"]; ok {
		t.Error("comment line was parsed as a key")
	}
	assertVal(t, m, "KEY", "value")
}

func TestParseSkipsBlankLines(t *testing.T) {
	m := parseString(t, "\n\nKEY=value\n\n")
	if len(m) != 1 {
		t.Errorf("expected 1 key, got %d", len(m))
	}
}

func TestParseEmptyValue(t *testing.T) {
	m := parseString(t, `KEY=`)
	assertVal(t, m, "KEY", "")
}

func TestParseEmptyQuotedValue(t *testing.T) {
	m := parseString(t, `KEY=""`)
	assertVal(t, m, "KEY", "")
}

func TestParseMultilineDoubleQuoted(t *testing.T) {
	m := parseString(t, "KEY=\"line1\nline2\"\nOTHER=val\n")
	assertVal(t, m, "KEY", "line1\nline2")
	assertVal(t, m, "OTHER", "val")
}

func TestWriteAndParseRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	original := map[string]string{
		"DB_URL":    "postgres://localhost/test",
		"API_KEY":   "s3cr3t!@#",
		"EMPTY_VAL": "",
		"MULTIWORD": "hello world",
	}

	if err := env.WriteEnvFile(path, original); err != nil {
		t.Fatalf("WriteEnvFile: %v", err)
	}

	parsed, err := env.ParseEnvFile(path)
	if err != nil {
		t.Fatalf("ParseEnvFile after write: %v", err)
	}

	for k, want := range original {
		got, ok := parsed[k]
		if !ok {
			t.Errorf("key %s missing after roundtrip", k)
			continue
		}
		if got != want {
			t.Errorf("key %s: got %q, want %q", k, got, want)
		}
	}
}

func TestWriteFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix file permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")

	if err := env.WriteEnvFile(path, map[string]string{"K": "v"}); err != nil {
		t.Fatalf("WriteEnvFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode: got %o, want 0600", info.Mode().Perm())
	}
}

func assertVal(t *testing.T, m map[string]string, key, want string) {
	t.Helper()
	got, ok := m[key]
	if !ok {
		t.Errorf("key %q not found", key)
		return
	}
	if got != want {
		t.Errorf("key %q: got %q, want %q", key, got, want)
	}
}
