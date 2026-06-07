// pubkey.go defines `envlock pubkey`.
// Prints the full age public key for the current user so they can share it
// with a teammate who will run `envlock grant <email> --key <age1...>`.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/config"
	"github.com/tunahandogan/envlock/internal/keys"
)

var pubkeyEmailFlag string

var pubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Print your age public key",
	Long: `Print the age public key for your local envlock identity.
Share this with a teammate so they can grant you vault access:

  envlock grant alice@team.com --key $(envlock pubkey --email alice@team.com)

With no flags, the command detects your email from the current project config.`,
	Args:    cobra.NoArgs,
	RunE:    runPubkey,
	Example: "  envlock pubkey\n  envlock pubkey --email alice@team.com",
}

func init() {
	pubkeyCmd.Flags().StringVar(&pubkeyEmailFlag, "email", "", "email whose key to print (defaults to current project user)")
	rootCmd.AddCommand(pubkeyCmd)
}

func runPubkey(cmd *cobra.Command, args []string) error {
	email := pubkeyEmailFlag

	if email == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting working directory: %w", err)
		}
		if config.ProjectInitialized(cwd) {
			cfg, err := config.LoadConfig(cwd)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			email = currentUserEmail(cfg)
		}
	}

	if email == "" {
		return fmt.Errorf("could not determine email.\n" +
			"Specify one with --email, or run 'envlock init' first")
	}

	identity, err := keys.LoadPrivateKey(email)
	if err != nil {
		return fmt.Errorf("loading private key for %s: %w\n"+
			"Run 'envlock init --email %s' to generate a keypair", email, err, email)
	}

	fmt.Println(keys.PublicKeyString(identity))
	return nil
}
