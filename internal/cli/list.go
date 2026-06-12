// list.go defines `envlock list` (alias: ls).
// Default output shows only key names (never values) for safety.
// Use --values to include values or --json for machine-readable output.
package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	listValuesFlag bool
	listJSONFlag   bool
)

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List secrets in the vault",
	Long: `Decrypt the vault and display secret keys.
Values are hidden by default to prevent accidental exposure.

Flags:
  --values   also print the secret values
  --json     output as JSON (for use in scripts)`,
	Args:    cobra.NoArgs,
	RunE:    runList,
	Example: "  envlock list\n  envlock ls --values\n  envlock list --json",
}

func init() {
	listCmd.Flags().BoolVar(&listValuesFlag, "values", false, "show secret values (use carefully)")
	listCmd.Flags().BoolVar(&listJSONFlag, "json", false, "output as JSON")
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	ctx, err := loadVaultCtx()
	if err != nil {
		return err
	}

	sortedKeys := ctx.vault.List()

	if len(sortedKeys) == 0 {
		fmt.Println("No secrets in vault.")
		fmt.Println("Add one with: envlock add KEY=value")
		return nil
	}

	if listJSONFlag {
		return printListJSON(ctx, sortedKeys)
	}

	printListTable(ctx, sortedKeys)
	return nil
}

// printListJSON writes JSON to stdout.
// Without --values: {"keys":["K1","K2"],"count":2}
// With --values:    {"count":2,"secrets":{"K1":"v1","K2":"v2"}}
func printListJSON(ctx *vaultCtx, sortedKeys []string) error {
	var payload any
	count := len(sortedKeys)

	if listValuesFlag {
		secrets := make(map[string]string, count)
		for _, k := range sortedKeys {
			v, _ := ctx.vault.Get(k)
			secrets[k] = v
		}
		payload = map[string]any{"count": count, "secrets": secrets}
	} else {
		payload = map[string]any{"count": count, "keys": sortedKeys}
	}

	enc, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	fmt.Println(string(enc))
	return nil
}

// printListTable renders a formatted table to stdout.
func printListTable(ctx *vaultCtx, sortedKeys []string) {
	bold := color.New(color.Bold)
	dim := color.New(color.FgHiBlack)

	// Compute column widths.
	nameW := len("NAME")
	for _, k := range sortedKeys {
		if len(k) > nameW {
			nameW = len(k)
		}
	}

	const maxValueDisplay = 40

	valueW := len("VALUE")
	if listValuesFlag {
		for _, k := range sortedKeys {
			v, _ := ctx.vault.Get(k)
			shown := min(len(v), maxValueDisplay)
			if shown > valueW {
				valueW = shown
			}
		}
	}

	// Header.
	sep := strings.Repeat("─", nameW+2+5+(func() int {
		if listValuesFlag {
			return valueW + 2
		}
		return 0
	})())

	if listValuesFlag {
		bold.Printf("%-*s  %-*s  %s\n", nameW, "NAME", valueW, "VALUE", "CHARS")
	} else {
		bold.Printf("%-*s  %s\n", nameW, "NAME", "CHARS")
	}
	dim.Println(sep)

	// Rows.
	for _, k := range sortedKeys {
		v, _ := ctx.vault.Get(k)
		if listValuesFlag {
			displayed := v
			if len(displayed) > maxValueDisplay {
				displayed = displayed[:maxValueDisplay-3] + "..."
			}
			fmt.Printf("%-*s  %-*s  %d\n", nameW, k, valueW, displayed, len(v))
		} else {
			fmt.Printf("%-*s  %d\n", nameW, k, len(v))
		}
	}

	// Footer.
	dim.Println(sep)
	updated := ctx.vault.Metadata.UpdatedAt.Format("2006-01-02 15:04:05 UTC")
	fmt.Printf("%d secret(s) total  •  last updated %s\n", len(sortedKeys), updated)
}
