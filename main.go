package main

import (
	"fmt"
	"github.com/compliance-framework/agent/cmd"
	"github.com/spf13/cobra"
	"os"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "cf",
		Short: "cf manages policies for the compliance framework",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Usage()
		},
	}

	rootCmd.AddCommand(cmd.AgentCmd())
	rootCmd.AddCommand(cmd.DownloadPluginCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
