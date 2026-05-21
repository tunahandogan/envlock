// Package cli defines all cobra commands for envlock.
// Sub-commands (lock, unlock, init, keygen, …) will be registered here.
package cli

import (
	"os"

	"github.com/spf13/cobra"
)

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

// Execute runs the root command. Called by main.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
