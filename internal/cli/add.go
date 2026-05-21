// add.go defines `envlock add KEY=VALUE`.
package cli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/vault"
)

// envKeyRE enforces conventional env-var naming: uppercase letters, digits,
// underscores; must start with a letter.
var envKeyRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

var addCmd = &cobra.Command{
	Use:   "add KEY=VALUE",
	Short: "Add or update a secret in the vault",
	Long: `Decrypt the vault, add (or overwrite) a secret, then re-encrypt for all
configured recipients. The vault file is written atomically so a crash during
save cannot corrupt existing data.`,
	Args:    cobra.ExactArgs(1),
	RunE:    runAdd,
	Example: "  envlock add DATABASE_URL=postgres://localhost/mydb",
}

func init() {
	rootCmd.AddCommand(addCmd)
}

func runAdd(cmd *cobra.Command, args []string) error {
	key, value, err := parseKeyValue(args[0])
	if err != nil {
		return err
	}

	ctx, err := loadVaultCtx()
	if err != nil {
		return err
	}

	if _, exists := ctx.vault.Get(key); exists {
		confirmed := false
		prompt := &survey.Confirm{
			Message: fmt.Sprintf("%s already exists. Overwrite?", key),
			Default: false,
		}
		if err := survey.AskOne(prompt, &confirmed); err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		if !confirmed {
			return fmt.Errorf("aborted")
		}
	}

	ctx.vault.Set(key, value)

	if err := vault.SaveVault(ctx.dir, ctx.vault, ctx.recipients); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Printf("✓ Added %s (encrypted for %d recipient(s))\n", key, len(ctx.recipients))
	fmt.Printf("\nTo commit: git add .envlock/vault.age && git commit -m \"chore: update secrets\"\n")
	return nil
}

// parseKeyValue splits "KEY=VALUE" on the first '=' and validates the key name.
func parseKeyValue(arg string) (key, value string, err error) {
	parts := strings.SplitN(arg, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid format %q: expected KEY=VALUE", arg)
	}
	key, value = parts[0], parts[1]
	if !envKeyRE.MatchString(key) {
		return "", "", fmt.Errorf(
			"invalid key %q: keys must match ^[A-Z][A-Z0-9_]*$ (uppercase letters, digits, underscores; must start with a letter)",
			key,
		)
	}
	return key, value, nil
}
