// grant.go defines `envlock grant <email> --key <age1...>`.
// It adds a new team member's public key to the project and re-encrypts the
// vault so they can decrypt it with their private key.
package cli

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/config"
	"github.com/tunahandogan/envlock/internal/crypto"
	"github.com/tunahandogan/envlock/internal/vault"
)

var grantKeyFlag string

var grantCmd = &cobra.Command{
	Use:   "grant <email>",
	Short: "Grant vault access to a new team member",
	Long: `Add a recipient's age public key to the project and re-encrypt all secrets
so they can decrypt the vault with their private key.

The recipient's public key is displayed when they run:
  envlock init --email their@email.com`,
	Args:    cobra.ExactArgs(1),
	RunE:    runGrant,
	Example: "  envlock grant alice@team.com --key age1qpzry9x8gf2...",
}

func init() {
	grantCmd.Flags().StringVar(&grantKeyFlag, "key", "", "recipient's age public key (age1...)")
	_ = grantCmd.MarkFlagRequired("key")
	rootCmd.AddCommand(grantCmd)
}

func runGrant(cmd *cobra.Command, args []string) error {
	email := strings.TrimSpace(args[0])
	publicKey := strings.TrimSpace(grantKeyFlag)

	// Validate inputs before touching disk.
	if !emailRE.MatchString(email) {
		return fmt.Errorf("invalid email address: %q", email)
	}
	if !strings.HasPrefix(publicKey, "age1") {
		return fmt.Errorf("invalid public key: age public keys must start with 'age1'.\n" +
			"Ask the recipient to share their public key from 'envlock init' output")
	}
	if _, err := crypto.ParseRecipient(publicKey); err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	cwd, err := requireInitialized()
	if err != nil {
		return err
	}
	cfg, err := config.LoadConfig(cwd)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Capture current user email before modifying config.
	addedBy := currentUserEmail(cfg)

	// Resolve local identity while the config still has the old recipient list.
	identity, err := getCurrentIdentity(cfg)
	if err != nil {
		return err
	}

	// AddRecipient validates for duplicates.
	if err := config.AddRecipient(cfg, email, publicKey, addedBy); err != nil {
		return err
	}

	// Build the new recipient list (now includes the new member).
	newRecipients, err := parseRecipients(cfg)
	if err != nil {
		return err
	}

	// Decrypt with current identity, re-encrypt for everyone (including the new member).
	v, err := vault.LoadVault(cwd, identity)
	if err != nil {
		return err
	}
	if err := vault.SaveVault(cwd, v, newRecipients); err != nil {
		return fmt.Errorf("re-encrypting vault: %w", err)
	}

	// Persist config only after the vault is safely written.
	if err := config.SaveConfig(cwd, cfg); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Printf("✓ Granted access to %s\n", email)
	green.Printf("✓ Re-encrypted %d secret(s) for %d recipient(s)\n",
		len(v.List()), len(cfg.Recipients))
	fmt.Printf("\nCommit the changes:\n")
	fmt.Printf("  git add .envlock/\n")
	fmt.Printf("  git commit -m \"grant envlock access to %s\"\n", email)
	return nil
}
