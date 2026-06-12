// rotate.go defines `envlock rotate KEY` and `envlock rotate --all`.
// Used after a security incident to replace secret values with new ones.
// Input is always hidden (no echo) so new values never appear in shell history.
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/vault"
)

var (
	rotateAllFlag   bool
	rotateStdinFlag bool
)

var rotateCmd = &cobra.Command{
	Use:   "rotate [KEY]",
	Short: "Replace a secret value with a new one",
	Long: `Securely update a secret value. Input is never echoed so the new value
does not appear in shell history or terminal scrollback.

Use --all to walk through every key in the vault (press Enter to skip any key).
This is the recommended workflow after a security incident.

  envlock rotate API_TOKEN
  envlock rotate --all`,
	Args:    cobra.MaximumNArgs(1),
	RunE:    runRotate,
	Example: "  envlock rotate STRIPE_SECRET\n  envlock rotate --all",
}

func init() {
	rotateCmd.Flags().BoolVar(&rotateAllFlag, "all", false, "rotate every secret in the vault interactively")
	rotateCmd.Flags().BoolVar(&rotateStdinFlag, "value-stdin", false, "read the new value from stdin (for scripts; single key only)")
	rootCmd.AddCommand(rotateCmd)
}

func runRotate(cmd *cobra.Command, args []string) error {
	if rotateAllFlag && len(args) > 0 {
		return fmt.Errorf("cannot specify a key together with --all")
	}
	if rotateAllFlag && rotateStdinFlag {
		return fmt.Errorf("--value-stdin only works with a single key, not --all")
	}
	if !rotateAllFlag && len(args) == 0 {
		return fmt.Errorf("specify a key to rotate, or use --all to rotate every secret")
	}

	ctx, err := loadVaultCtx()
	if err != nil {
		return err
	}

	if rotateAllFlag {
		return rotateAll(ctx)
	}
	return rotateSingle(ctx, args[0])
}

func rotateSingle(ctx *vaultCtx, key string) error {
	if _, ok := ctx.vault.Get(key); !ok {
		return fmt.Errorf("%s: key not found in vault.\n"+
			"Run 'envlock list' to see available keys", key)
	}

	var newValue string
	if rotateStdinFlag {
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("reading value from stdin: %w", err)
		}
		newValue = strings.TrimRight(line, "\r\n")
	} else if err := survey.AskOne(&survey.Password{
		Message: fmt.Sprintf("New value for %s:", key),
	}, &newValue); err != nil {
		return fmt.Errorf("reading value: %w", err)
	}
	if newValue == "" {
		return fmt.Errorf("value cannot be empty. Use 'envlock remove %s' to delete a key", key)
	}

	ctx.vault.Set(key, newValue)

	if err := vault.SaveVaultEnv(ctx.dir, ctx.env, ctx.vault, ctx.recipients); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	color.New(color.FgGreen, color.Bold).Printf("✓ Rotated %s\n", key)
	fmt.Printf("\nTo commit: git add .envlock/vault.age && git commit -m \"chore: rotate secrets\"\n")
	return nil
}

func rotateAll(ctx *vaultCtx) error {
	keys := ctx.vault.List()
	if len(keys) == 0 {
		return fmt.Errorf("vault is empty — nothing to rotate")
	}

	color.New(color.FgYellow, color.Bold).Printf(
		"⚠  Rotating all %d secret(s). Press Enter to leave a key unchanged.\n\n", len(keys))

	updates := make(map[string]string, len(keys))
	for _, key := range keys {
		var newValue string
		if err := survey.AskOne(&survey.Password{
			Message: fmt.Sprintf("New value for %s (Enter to skip):", key),
		}, &newValue); err != nil {
			return fmt.Errorf("reading value for %s: %w", key, err)
		}
		if newValue != "" {
			updates[key] = newValue
		}
	}

	if len(updates) == 0 {
		fmt.Println("No keys updated.")
		return nil
	}

	// Show summary before writing.
	fmt.Printf("\n%d key(s) will be updated:\n", len(updates))
	yellow := color.New(color.FgYellow)
	for _, k := range keys {
		if _, ok := updates[k]; ok {
			yellow.Printf("  ~ %s\n", k)
		}
	}
	fmt.Println()

	confirmed := false
	if err := survey.AskOne(&survey.Confirm{
		Message: fmt.Sprintf("Write %d rotation(s) to vault?", len(updates)),
		Default: true,
	}, &confirmed); err != nil {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if !confirmed {
		return fmt.Errorf("aborted")
	}

	for k, v := range updates {
		ctx.vault.Set(k, v)
	}

	if err := vault.SaveVaultEnv(ctx.dir, ctx.env, ctx.vault, ctx.recipients); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	color.New(color.FgGreen, color.Bold).Printf("✓ Rotated %d secret(s)\n", len(updates))
	fmt.Printf("\nTo commit: git add .envlock/vault.age && git commit -m \"chore: rotate secrets\"\n")
	return nil
}
