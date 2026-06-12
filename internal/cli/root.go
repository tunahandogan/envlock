// Package cli defines all cobra commands for envlock.
// Sub-commands (lock, unlock, init, keygen, …) will be registered here.
package cli

import (
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/keys"
)

// envFlag selects which vault environment commands operate on.
// Empty means the default environment (.envlock/vault.age).
var envFlag string

var rootCmd = &cobra.Command{
	Use:   "envlock",
	Short: "envlock – encrypted env management for teams",
	Long: `envlock encrypts your .env files with age encryption so you can safely
commit and share them across your team via version control.`,
	// Show help when invoked with no sub-command.
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
	// Suppress usage output on runtime errors; only show it for flag parse errors.
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&envFlag, "env", "",
		"vault environment to operate on (e.g. production); default is the shared vault")

	// Passphrase resolution for passphrase-protected private keys:
	// ENVLOCK_PASSPHRASE (for scripts and CI) wins over the interactive prompt.
	keys.PassphrasePrompt = func(email string) (string, error) {
		if p := os.Getenv("ENVLOCK_PASSPHRASE"); p != "" {
			return p, nil
		}
		passphrase := ""
		prompt := &survey.Password{
			Message: fmt.Sprintf("Passphrase for key %s:", email),
		}
		if err := survey.AskOne(prompt, &passphrase); err != nil {
			return "", err
		}
		return passphrase, nil
	}
}

// Execute runs the root command. Called by main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
