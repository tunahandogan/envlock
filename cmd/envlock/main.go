// Command envlock is the CLI entry point.
// All command logic lives in internal/cli; main only delegates.
package main

import "github.com/tunahandogan/envlock/internal/cli"

func main() {
	cli.Execute()
}
