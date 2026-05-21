// remove.go defines `envlock remove KEY` (alias: rm).
package cli

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/vault"
)

var removeForceFlag bool

var removeCmd = &cobra.Command{
	Use:     "remove KEY",
	Aliases: []string{"rm"},
	Short:   "Remove a secret from the vault",
	Long: `Decrypt the vault, delete KEY, then re-encrypt for all configured recipients.
A confirmation prompt is shown unless --force is passed.`,
	Args:    cobra.ExactArgs(1),
	RunE:    runRemove,
	Example: "  envlock remove STRIPE_KEY\n  envlock rm OLD_TOKEN --force",
}

func init() {
	removeCmd.Flags().BoolVar(&removeForceFlag, "force", false, "skip the confirmation prompt")
	rootCmd.AddCommand(removeCmd)
}

func runRemove(cmd *cobra.Command, args []string) error {
	key := args[0]

	ctx, err := loadVaultCtx()
	if err != nil {
		return err
	}

	if _, ok := ctx.vault.Get(key); !ok {
		return fmt.Errorf("%s: key not found in vault.\n"+
			"Run 'envlock list' to see available keys", key)
	}

	if !removeForceFlag {
		confirmed := false
		prompt := &survey.Confirm{
			Message: fmt.Sprintf("Permanently remove %s from the vault?", key),
			Default: false,
		}
		if err := survey.AskOne(prompt, &confirmed); err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		if !confirmed {
			return fmt.Errorf("aborted")
		}
	}

	ctx.vault.Delete(key)

	if err := vault.SaveVault(ctx.dir, ctx.vault, ctx.recipients); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	color.New(color.FgGreen, color.Bold).Printf("✓ Removed %s\n", key)
	fmt.Printf("\nTo commit: git add .envlock/vault.age && git commit -m \"chore: update secrets\"\n")
	return nil
}
