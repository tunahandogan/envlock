// init.go defines the `envlock init` command.
// It generates an age keypair for the user and bootstraps the project config.
package cli

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/config"
	"github.com/tunahandogan/envlock/internal/gitignore"
	"github.com/tunahandogan/envlock/internal/keys"
)

// emailRE is a basic RFC-5321 email validator — not exhaustive, but catches obvious mistakes.
var emailRE = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

var (
	initEmailFlag      string
	initPassphraseFlag bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize envlock in the current project",
	Long: `Generate an age keypair and create .envlock/config.yaml for the project.

The private key is written to ~/.envlock/keys/<email>.key (mode 0600) and
never leaves your machine. The public key is stored in config.yaml so that
teammates can encrypt secrets for you.`,
	RunE: runInit,
}

// init registers initCmd with the root command when the cli package loads.
func init() {
	initCmd.Flags().StringVarP(&initEmailFlag, "email", "e", "", "your email address (names the key file)")
	initCmd.Flags().BoolVar(&initPassphraseFlag, "passphrase", false, "protect the private key with a passphrase")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	email, err := resolveEmail(initEmailFlag)
	if err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting working directory: %w", err)
	}

	if config.ProjectInitialized(cwd) {
		return fmt.Errorf("project already initialized (.envlock/ already exists)")
	}

	if err := handleExistingKey(email); err != nil {
		return err
	}

	passphrase := ""
	if initPassphraseFlag {
		passphrase, err = promptNewPassphrase()
		if err != nil {
			return err
		}
	}

	identity, err := keys.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generating keypair: %w", err)
	}

	keyPath, err := keys.SavePrivateKeyWithPassphrase(identity, email, passphrase)
	if err != nil {
		return fmt.Errorf("saving private key: %w", err)
	}

	publicKey := keys.PublicKeyString(identity)

	if err := config.InitConfig(cwd, email, publicKey); err != nil {
		return fmt.Errorf("creating project config: %w", err)
	}

	gitignoreAdded, err := gitignore.EnsureEntries(cwd, []string{".env", ".env.*", "!.env.example"})
	if err != nil {
		// Non-fatal: warn but don't abort.
		fmt.Fprintf(os.Stderr, "warning: could not update .gitignore: %v\n", err)
	}

	printSuccess(email, keyPath, publicKey, gitignoreAdded)
	return nil
}

// resolveEmail returns the validated email, prompting interactively if empty.
func resolveEmail(flag string) (string, error) {
	email := strings.TrimSpace(flag)
	if email == "" {
		if err := survey.AskOne(&survey.Input{Message: "Your email address:"}, &email); err != nil {
			return "", fmt.Errorf("reading email: %w", err)
		}
		email = strings.TrimSpace(email)
	}
	if !emailRE.MatchString(email) {
		return "", fmt.Errorf("invalid email address: %q", email)
	}
	return email, nil
}

// promptNewPassphrase asks for a new passphrase twice and verifies the entries match.
// ENVLOCK_PASSPHRASE skips the prompt for non-interactive use (scripts, CI).
func promptNewPassphrase() (string, error) {
	if p := os.Getenv("ENVLOCK_PASSPHRASE"); p != "" {
		return p, nil
	}
	first := ""
	if err := survey.AskOne(&survey.Password{Message: "Choose a passphrase for your private key:"}, &first); err != nil {
		return "", fmt.Errorf("reading passphrase: %w", err)
	}
	if strings.TrimSpace(first) == "" {
		return "", fmt.Errorf("passphrase cannot be empty")
	}
	second := ""
	if err := survey.AskOne(&survey.Password{Message: "Confirm passphrase:"}, &second); err != nil {
		return "", fmt.Errorf("reading passphrase confirmation: %w", err)
	}
	if first != second {
		return "", fmt.Errorf("passphrases do not match")
	}
	return first, nil
}

// handleExistingKey asks for confirmation when a key file for email already exists.
func handleExistingKey(email string) error {
	exists, err := keys.KeyExists(email)
	if err != nil {
		return fmt.Errorf("checking existing key: %w", err)
	}
	if !exists {
		return nil
	}

	overwrite := false
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("A key for %s already exists. Overwrite?", email),
		Default: false,
	}
	if err := survey.AskOne(prompt, &overwrite); err != nil {
		return fmt.Errorf("reading confirmation: %w", err)
	}
	if !overwrite {
		return fmt.Errorf("aborted by user")
	}
	return nil
}

// printSuccess prints the coloured summary after a successful init.
func printSuccess(email, keyPath, publicKey string, gitignoreAdded []string) {
	green := color.New(color.FgGreen, color.Bold)

	green.Printf("✓ Keypair generated\n")
	green.Printf("✓ Private key saved to %s\n", displayPath(keyPath))
	green.Printf("✓ Public key: %s\n", publicKey)
	green.Printf("✓ Project initialized at .envlock/config.yaml\n")
	if len(gitignoreAdded) > 0 {
		green.Printf("✓ Added %d line(s) to .gitignore (%s)\n",
			len(gitignoreAdded), strings.Join(gitignoreAdded, ", "))
	}
	fmt.Println()
	fmt.Printf("Share your public key with teammates:  envlock pubkey\n")
	fmt.Printf("Grant a teammate access:               envlock grant <email> --key <age1...>\n")
	fmt.Printf("Encrypt your first secret:             envlock add KEY=value\n")
}

// displayPath replaces the home directory prefix with ~ for a shorter display.
func displayPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if strings.HasPrefix(path, home) {
		return "~" + path[len(home):]
	}
	return path
}
