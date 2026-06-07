// version.go defines `envlock version`.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags "-X ...version.Version=v1.2.3".
// Falls back to "dev" for local builds.
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the envlock version",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("envlock %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
