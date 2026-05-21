// pull.go defines `envlock pull`.
// It decrypts the vault and writes all secrets to a .env file.
package cli

import (
	"fmt"
	"os"
	"sort"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/env"
)

var (
	pullForceFlag  bool
	pullOutputFlag string
)

var pullCmd = &cobra.Command{
	Use:   "pull",
	Short: "Write vault secrets to a .env file",
	Long: `Decrypt the vault and write all secrets to a .env file.

If the target file already exists, the differences are shown before prompting
to overwrite. Use --force to skip the prompt.

The generated .env file is marked in your .gitignore by 'envlock init'.
Never commit it — use 'git add .envlock/vault.age' instead.`,
	Args:    cobra.NoArgs,
	RunE:    runPull,
	Example: "  envlock pull\n  envlock pull --output .env.local\n  envlock pull --force",
}

func init() {
	pullCmd.Flags().BoolVar(&pullForceFlag, "force", false, "overwrite existing file without prompting")
	pullCmd.Flags().StringVarP(&pullOutputFlag, "output", "o", ".env", "output file path")
	rootCmd.AddCommand(pullCmd)
}

func runPull(cmd *cobra.Command, args []string) error {
	ctx, err := loadVaultCtx()
	if err != nil {
		return err
	}

	// Build vault snapshot as a plain map.
	vaultSecrets := vaultToMap(ctx)

	outPath := pullOutputFlag

	// If file exists and we're not forcing, compute and display the diff.
	if _, statErr := os.Stat(outPath); statErr == nil && !pullForceFlag {
		existing, parseErr := env.ParseEnvFile(outPath)
		if parseErr == nil {
			diff := computeDiff(existing, vaultSecrets)
			if diff.empty() {
				color.New(color.FgGreen).Printf("%s is already up to date (%d variables)\n",
					outPath, len(vaultSecrets))
				return nil
			}
			printPullDiff(outPath, diff)
		} else {
			fmt.Printf("%s exists but could not be parsed. It will be replaced.\n", outPath)
		}

		confirmed := false
		if err := survey.AskOne(&survey.Confirm{
			Message: fmt.Sprintf("Overwrite %s?", outPath),
			Default: false,
		}, &confirmed); err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		if !confirmed {
			return fmt.Errorf("aborted")
		}
	}

	if err := env.WriteEnvFile(outPath, vaultSecrets); err != nil {
		return err
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Printf("✓ Wrote %d variable(s) to %s\n", len(vaultSecrets), outPath)
	return nil
}

// ── diff helpers ──────────────────────────────────────────────────────────────

type envDiff struct {
	adds    []string // in desired (vault), not in existing (.env)
	updates []string // in both, different value
	removes []string // in existing (.env), not in desired (vault)
}

func (d envDiff) empty() bool {
	return len(d.adds) == 0 && len(d.updates) == 0 && len(d.removes) == 0
}

// computeDiff compares existing (current file) with desired (vault).
func computeDiff(existing, desired map[string]string) envDiff {
	var d envDiff
	for k, dv := range desired {
		if ev, ok := existing[k]; !ok {
			d.adds = append(d.adds, k)
		} else if ev != dv {
			d.updates = append(d.updates, k)
		}
	}
	for k := range existing {
		if _, ok := desired[k]; !ok {
			d.removes = append(d.removes, k)
		}
	}
	sort.Strings(d.adds)
	sort.Strings(d.updates)
	sort.Strings(d.removes)
	return d
}

func printPullDiff(path string, d envDiff) {
	bold := color.New(color.Bold)
	bold.Printf("Changes that would be applied to %s:\n", path)

	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)

	for _, k := range d.adds {
		green.Printf("  + %-30s (new)\n", k)
	}
	for _, k := range d.updates {
		yellow.Printf("  ~ %-30s (value changed)\n", k)
	}
	for _, k := range d.removes {
		red.Printf("  - %-30s (not in vault — will be removed)\n", k)
	}
	fmt.Println()
}

// vaultToMap extracts all secrets from ctx into a plain string map.
func vaultToMap(ctx *vaultCtx) map[string]string {
	m := make(map[string]string, len(ctx.vault.List()))
	for _, k := range ctx.vault.List() {
		v, _ := ctx.vault.Get(k)
		m[k] = v
	}
	return m
}
