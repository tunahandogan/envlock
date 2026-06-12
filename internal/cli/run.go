// run.go defines `envlock run -- <command> [args...]`.
// It decrypts the vault, merges secrets into the current process environment,
// and spawns the requested command without writing any file to disk.
// This is the most secure way to use envlock in development.
package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run -- <command> [args...]",
	Short: "Run a command with vault secrets injected into the environment",
	Long: `Decrypt the vault and spawn a subprocess with the secrets available as
environment variables. No .env file is written to disk.

Vault secrets are merged on top of the existing process environment. If a
key already exists in the environment, the vault value takes precedence.

Use -- to separate envlock flags from the command and its flags:
  envlock run -- npm start
  envlock run -- python manage.py runserver

On Windows, shell built-ins require an explicit cmd /c prefix:
  envlock run -- cmd /c dir`,
	Args:               cobra.MinimumNArgs(1),
	RunE:               runRun,
	DisableFlagParsing: false,
	Example:            "  envlock run -- npm start\n  envlock run -- pytest -v\n  envlock run -- printenv | grep DB",
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified. Usage: envlock run -- <command> [args...]")
	}

	ctx, err := loadVaultCtx()
	if err != nil {
		return err
	}

	// Merge os.Environ() with vault secrets (vault wins on collision).
	mergedEnv := mergeEnv(os.Environ(), ctx)

	command, cmdArgs := resolveCommand(args[0], args[1:])

	child := exec.Command(command, cmdArgs...)
	child.Env = mergedEnv
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr

	if err := child.Run(); err != nil {
		// Propagate the subprocess exit code so callers can rely on it.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		return fmt.Errorf("command failed: %w", err)
	}
	return nil
}

// mergeEnv builds an env slice starting from base, then overlaying vault secrets.
func mergeEnv(base []string, ctx *vaultCtx) []string {
	// Index current environment for O(1) lookup.
	envMap := make(map[string]string, len(base))
	for _, pair := range base {
		k, v, _ := strings.Cut(pair, "=")
		envMap[k] = v
	}
	// Vault values take precedence.
	for _, k := range ctx.vault.List() {
		v, _ := ctx.vault.Get(k)
		envMap[k] = v
	}
	// Reconstruct as slice.
	result := make([]string, 0, len(envMap))
	for k, v := range envMap {
		result = append(result, k+"="+v)
	}
	return result
}

// resolveCommand handles Windows .cmd/.bat wrapper scripts that require cmd.exe.
func resolveCommand(name string, args []string) (string, []string) {
	if runtime.GOOS != "windows" {
		return name, args
	}
	resolved, err := exec.LookPath(name)
	if err != nil {
		return name, args
	}
	lower := strings.ToLower(resolved)
	if strings.HasSuffix(lower, ".cmd") || strings.HasSuffix(lower, ".bat") {
		// Batch files must be executed through cmd.exe.
		return "cmd", append([]string{"/c", resolved}, args...)
	}
	return name, args
}
