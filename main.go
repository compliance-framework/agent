package main

import (
	"fmt"
	"github.com/compliance-framework/agent/cmd"
	"github.com/spf13/cobra"
	"os"
)

// version is set with -X main.version=...: by goreleaser's default ldflags and
// by the Dockerfiles' VERSION build arg.
var version = "dev"

func main() {
	cmd.SetAgentVersion(version)

	var rootCmd = &cobra.Command{
		Use:   "cf",
		Short: "cf manages policies for the compliance framework",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}

	rootCmd.AddCommand(cmd.AgentCmd())
	rootCmd.AddCommand(cmd.DownloadPluginCmd())
	rootCmd.AddCommand(cmd.SubmitEvidenceCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
