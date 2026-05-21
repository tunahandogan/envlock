// revoke.go defines `envlock revoke <email>`.
// It removes a team member from the recipient list and re-encrypts the vault
// without their key, blocking future decryption with their private key.
//
// Security note: re-encryption prevents access to the *current* vault state.
// Past commits still contain versions encrypted with the old recipient list.
// If the removal is for security reasons, rotate all affected secrets immediately.
package cli

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/config"
	"github.com/tunahandogan/envlock/internal/vault"
)

var revokeForceFlag bool

var revokeCmd = &cobra.Command{
	Use:   "revoke <email>",
	Short: "Remove a team member's vault access",
	Long: `Remove a recipient from the project and re-encrypt all secrets without
their key, so future decryption with their private key is impossible.

WARNING: Old encrypted vault versions remain in git history. If the removal
is for security reasons, rotate your secrets immediately after revoking.`,
	Args:    cobra.ExactArgs(1),
	RunE:    runRevoke,
	Example: "  envlock revoke alice@team.com",
}

func init() {
	revokeCmd.Flags().BoolVar(&revokeForceFlag, "force", false, "skip confirmation prompt (use in scripts)")
	rootCmd.AddCommand(revokeCmd)
}

func runRevoke(cmd *cobra.Command, args []string) error {
	email := args[0]

	cwd, err := requireInitialized()
	if err != nil {
		return err
	}
	cfg, err := config.LoadConfig(cwd)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Verify the email is actually in the recipient list.
	found := false
	for _, r := range cfg.Recipients {
		if r.Email == email {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%s: not found in recipients list.\nRun 'envlock recipients' to see current members", email)
	}

	// Never leave the vault with zero recipients.
	if len(cfg.Recipients) == 1 {
		return fmt.Errorf(
			"cannot revoke the last recipient — the vault would be permanently unreadable.\n" +
				"Grant access to another team member first: envlock grant <email> --key <age1...>",
		)
	}

	// Warn if the user is revoking their own access.
	selfEmail := currentUserEmail(cfg)
	if email == selfEmail {
		yellow := color.New(color.FgYellow, color.Bold)
		yellow.Fprintln(os.Stderr, "⚠  You are revoking your own access.")
		fmt.Fprintln(os.Stderr, "   After this you will no longer be able to decrypt this vault on this machine.")
		fmt.Fprintln(os.Stderr)
	}

	// Resolve local identity while the config still has the full recipient list.
	identity, err := getCurrentIdentity(cfg)
	if err != nil {
		return err
	}

	// Confirmation — this is a significant, hard-to-reverse operation.
	if !revokeForceFlag {
		confirmed := false
		prompt := &survey.Confirm{
			Message: fmt.Sprintf("Remove %s and re-encrypt all secrets without their key?", email),
			Default: false,
		}
		if err := survey.AskOne(prompt, &confirmed); err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		if !confirmed {
			return fmt.Errorf("aborted")
		}
	}

	// Remove from in-memory config.
	if err := config.RemoveRecipient(cfg, email); err != nil {
		return err
	}

	// Build the reduced recipient list (does not include the removed email).
	newRecipients, err := parseRecipients(cfg)
	if err != nil {
		return err
	}

	// Decrypt vault, re-encrypt without the removed recipient.
	v, err := vault.LoadVault(cwd, identity)
	if err != nil {
		return err
	}
	if err := vault.SaveVault(cwd, v, newRecipients); err != nil {
		return fmt.Errorf("re-encrypting vault: %w", err)
	}

	// Persist config only after the vault is safely updated.
	if err := config.SaveConfig(cwd, cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)

	green.Printf("✓ Revoked %s from future access\n", email)
	green.Printf("✓ Re-encrypted %d secret(s) for %d remaining recipient(s)\n",
		len(v.List()), len(cfg.Recipients))

	fmt.Println()
	yellow.Println("⚠  IMPORTANT: git history still contains old encrypted versions.")
	fmt.Printf("   %s can still decrypt past vault snapshots from git commits.\n", email)
	fmt.Println("   If this is a security incident, rotate the affected secrets immediately:")
	fmt.Println("   envlock rotate ALL   (coming soon)")
	fmt.Println()
	fmt.Printf("Commit the changes:\n")
	fmt.Printf("  git add .envlock/\n")
	fmt.Printf("  git commit -m \"revoke envlock access from %s\"\n", email)
	return nil
}
