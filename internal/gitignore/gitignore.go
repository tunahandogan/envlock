// Package gitignore manages .gitignore entries for envlock projects.
package gitignore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	gitignoreFile  = ".gitignore"
	gitignorePerms = 0o644
)

// EnsureEntries adds the given lines to the .gitignore file at projectPath.
// Lines already present (exact match after trimming) are skipped.
// The file is created if it does not exist.
// Returns the list of lines that were actually added.
func EnsureEntries(projectPath string, entries []string) ([]string, error) {
	path := filepath.Join(projectPath, gitignoreFile)

	existing := make(map[string]struct{})
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading .gitignore: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		existing[strings.TrimSpace(line)] = struct{}{}
	}

	var toAdd []string
	for _, entry := range entries {
		if _, ok := existing[entry]; !ok {
			toAdd = append(toAdd, entry)
		}
	}
	if len(toAdd) == 0 {
		return nil, nil
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, gitignorePerms)
	if err != nil {
		return nil, fmt.Errorf("opening .gitignore: %w", err)
	}
	defer f.Close()

	// Ensure a blank separator if the file already has content.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		fmt.Fprintln(f)
	}
	if len(data) > 0 {
		fmt.Fprintln(f)
	}
	fmt.Fprintln(f, "# envlock — never commit plain-text env files")
	for _, entry := range toAdd {
		fmt.Fprintln(f, entry)
	}
	return toAdd, nil
}
