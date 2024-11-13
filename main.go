package main

import (
	"fmt"
	"os"

	"github.com/chris-cmsoft/concom/cmd"
	"github.com/spf13/cobra"
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

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
