// recipients.go defines `envlock recipients`.
// It lists every team member who currently has access to the vault.
package cli

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/config"
	"github.com/tunahandogan/envlock/internal/keys"
)

const (
	pubKeyDisplayLen = 20 // chars of the public key shown before "..."
)

var recipientsCmd = &cobra.Command{
	Use:   "recipients",
	Short: "List everyone who has vault access",
	Long:  `Show all configured recipients and their age public keys. The current user is marked with *.`,
	Args:  cobra.NoArgs,
	RunE:  runRecipients,
}

func init() {
	rootCmd.AddCommand(recipientsCmd)
}

func runRecipients(cmd *cobra.Command, args []string) error {
	cwd, err := requireInitialized()
	if err != nil {
		return err
	}
	cfg, err := config.LoadConfig(cwd)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if len(cfg.Recipients) == 0 {
		fmt.Println("No recipients configured.")
		fmt.Println("Add one with: envlock grant <email> --key <age1...>")
		return nil
	}

	// Identify the local user.
	self := currentUserEmail(cfg)

	// Compute column widths.
	emailW := len("EMAIL")
	for _, r := range cfg.Recipients {
		if len(r.Email) > emailW {
			emailW = len(r.Email)
		}
	}

	bold := color.New(color.Bold)
	dim := color.New(color.FgHiBlack)
	green := color.New(color.FgGreen, color.Bold)

	sepLen := 2 + emailW + 2 + pubKeyDisplayLen + 3 + 2 + len("ADDED ON") + 2 + len("ADDED BY")
	sep := strings.Repeat("─", sepLen)

	// Header (leading spaces align with the marker column).
	bold.Printf("  %-*s  %-*s  %-10s  %s\n",
		emailW, "EMAIL",
		pubKeyDisplayLen, "PUBLIC KEY",
		"ADDED ON", "ADDED BY")
	dim.Println(sep)

	for _, r := range cfg.Recipients {
		marker := "  "
		emailStr := fmt.Sprintf("%-*s", emailW, r.Email)
		if r.Email == self {
			marker = "* "
			emailStr = color.GreenString("%-*s", emailW, r.Email)
		}

		// Truncate the public key for display.
		pk := r.PublicKey
		var pkDisplay string
		if len(pk) > pubKeyDisplayLen {
			pkDisplay = pk[:pubKeyDisplayLen-3] + "..."
		} else {
			pkDisplay = pk
		}

		addedOn := "-"
		if r.AddedOn != nil {
			addedOn = r.AddedOn.Format("2006-01-02")
		}
		addedBy := r.AddedBy
		if addedBy == "" {
			addedBy = "-"
		}

		fmt.Printf("%s%s  %-*s  %-10s  %s\n",
			marker, emailStr,
			pubKeyDisplayLen, pkDisplay,
			addedOn, addedBy)
	}

	dim.Println(sep)

	// Check whether we found a local key.
	localKeyFound := false
	for _, r := range cfg.Recipients {
		ok, _ := keys.KeyExists(r.Email)
		if ok {
			localKeyFound = true
			break
		}
	}

	fmt.Printf("%d recipient(s) total\n", len(cfg.Recipients))
	if localKeyFound {
		green.Println("* = you (local private key found)")
	} else {
		color.New(color.FgYellow).Println("⚠  No local private key found. Run 'envlock init' to generate one.")
	}
	return nil
}
