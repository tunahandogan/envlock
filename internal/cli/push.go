// push.go defines `envlock push`.
// It reads a .env file, computes what changed versus the vault, shows a diff,
// and writes only the new/changed keys into the vault.
//
// Vault-only keys are NEVER removed by push — use 'envlock remove KEY' for that.
package cli

import (
	"fmt"
	"sort"

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/tunahandogan/envlock/internal/env"
	"github.com/tunahandogan/envlock/internal/vault"
)

var (
	pushInputFlag string
	pushForceFlag bool
)

var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Sync .env file contents into the vault",
	Long: `Read a .env file and push new or changed keys into the vault.

Keys that exist in the vault but NOT in the .env file are LEFT UNTOUCHED.
To remove a key from the vault, use: envlock remove KEY

⚠  push is a broad operation. For day-to-day work prefer:
     envlock add KEY=value      (targeted, explicit)
     envlock remove KEY         (explicit removal)`,
	Args:    cobra.NoArgs,
	RunE:    runPush,
	Example: "  envlock push\n  envlock push --input .env.production\n  envlock push --force",
}

func init() {
	pushCmd.Flags().StringVarP(&pushInputFlag, "input", "i", ".env", "source .env file to read from")
	pushCmd.Flags().BoolVar(&pushForceFlag, "force", false, "skip confirmation prompt")
	rootCmd.AddCommand(pushCmd)
}

func runPush(cmd *cobra.Command, args []string) error {
	ctx, err := loadVaultCtx()
	if err != nil {
		return err
	}

	fileSecrets, err := env.ParseEnvFile(pushInputFlag)
	if err != nil {
		return fmt.Errorf("reading %s: %w", pushInputFlag, err)
	}
	if len(fileSecrets) == 0 {
		return fmt.Errorf("%s is empty or contains no valid KEY=VALUE pairs", pushInputFlag)
	}

	// Compute changes: what the .env adds or changes relative to the vault.
	var adds, updates []string
	for k := range fileSecrets {
		existing, ok := ctx.vault.Get(k)
		if !ok {
			adds = append(adds, k)
		} else if existing != fileSecrets[k] {
			updates = append(updates, k)
		}
	}
	sort.Strings(adds)
	sort.Strings(updates)

	// Keys only in vault (not in .env) — informational.
	var vaultOnly []string
	for _, k := range ctx.vault.List() {
		if _, ok := fileSecrets[k]; !ok {
			vaultOnly = append(vaultOnly, k)
		}
	}

	if len(adds) == 0 && len(updates) == 0 {
		color.New(color.FgGreen).Printf("Vault is already up to date with %s\n", pushInputFlag)
		if len(vaultOnly) > 0 {
			fmt.Printf("%d vault-only key(s) unchanged: %v\n", len(vaultOnly), vaultOnly)
		}
		return nil
	}

	printPushDiff(pushInputFlag, adds, updates, vaultOnly)

	if !pushForceFlag {
		confirmed := false
		if err := survey.AskOne(&survey.Confirm{
			Message: fmt.Sprintf("Push %d change(s) to vault?", len(adds)+len(updates)),
			Default: false,
		}, &confirmed); err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		if !confirmed {
			return fmt.Errorf("aborted")
		}
	}

	for _, k := range adds {
		ctx.vault.Set(k, fileSecrets[k])
	}
	for _, k := range updates {
		ctx.vault.Set(k, fileSecrets[k])
	}

	if err := vault.SaveVaultEnv(ctx.dir, ctx.env, ctx.vault, ctx.recipients); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	green := color.New(color.FgGreen, color.Bold)
	green.Printf("✓ Pushed %d addition(s) and %d update(s) to vault\n", len(adds), len(updates))
	fmt.Printf("\nTo commit: git add .envlock/vault.age && git commit -m \"chore: update secrets\"\n")
	return nil
}

func printPushDiff(source string, adds, updates, vaultOnly []string) {
	bold := color.New(color.Bold)
	bold.Printf("Changes from %s → vault:\n", source)

	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.FgHiBlack)

	for _, k := range adds {
		green.Printf("  + %-30s (new — will be added to vault)\n", k)
	}
	for _, k := range updates {
		yellow.Printf("  ~ %-30s (value changed — will be updated)\n", k)
	}
	if len(vaultOnly) > 0 {
		fmt.Println()
		dim.Printf("  Vault-only keys preserved (%d): ", len(vaultOnly))
		for i, k := range vaultOnly {
			if i > 0 {
				dim.Print(", ")
			}
			dim.Print(k)
		}
		fmt.Println()
	}
	fmt.Println()
}
