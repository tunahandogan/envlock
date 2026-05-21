// get.go defines `envlock get KEY`.
// The command is deliberately minimal so its stdout can be piped directly:
//   export DB=$(envlock get DATABASE_URL)
package cli

import (
	"fmt"
	"os"

	"github.com/atotto/clipboard"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var getCopyFlag bool

var getCmd = &cobra.Command{
	Use:   "get KEY",
	Short: "Print a secret value to stdout",
	Long: `Decrypt the vault and print the value of KEY to stdout.
Output is intentionally plain so the command is pipe-friendly:

  export TOKEN=$(envlock get API_TOKEN)

Use --copy to write the value to the clipboard instead.`,
	Args:    cobra.ExactArgs(1),
	RunE:    runGet,
	Example: "  envlock get DATABASE_URL\n  envlock get API_TOKEN --copy",
}

func init() {
	getCmd.Flags().BoolVar(&getCopyFlag, "copy", false, "copy value to clipboard instead of printing")
	rootCmd.AddCommand(getCmd)
}

func runGet(cmd *cobra.Command, args []string) error {
	key := args[0]

	ctx, err := loadVaultCtx()
	if err != nil {
		return err
	}

	value, ok := ctx.vault.Get(key)
	if !ok {
		// Write to stderr explicitly; cobra will also prefix with "Error: "
		// when RunE returns a non-nil error, which is what we want.
		return fmt.Errorf("%s: key not found in vault.\n"+
			"Run 'envlock list' to see available keys", key)
	}

	if getCopyFlag {
		if err := clipboard.WriteAll(value); err != nil {
			return fmt.Errorf("copying to clipboard: %w", err)
		}
		color.New(color.FgGreen, color.Bold).Fprintf(os.Stderr, "✓ %s copied to clipboard\n", key)
		return nil
	}

	fmt.Println(value)
	return nil
}
