package main

import (
	"fmt"
	"github.com/chris-cmsoft/concom/cmd"
	"github.com/spf13/cobra"
	"os"
)

func main() {

	var rootCmd = &cobra.Command{
		Use:   "cf",
		Short: "cf manages policies for the compliance framework",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("cf called")
			// Do Stuff Here
		},
	}

	rootCmd.AddCommand(cmd.VerifyCmd())
	rootCmd.AddCommand(cmd.AgentCmd())
	rootCmd.AddCommand(cmd.DownloadPluginCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
