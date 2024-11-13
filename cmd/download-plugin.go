package cmd

import (
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/rego"
	"github.com/spf13/cobra"
	"log"
	"os"
)

func DownloadPluginCmd() *cobra.Command {
	var agentCmd = &cobra.Command{
		Use:   "download-plugin",
		Short: "downloads plugins from OCI or URLs",
		Run: func(cmd *cobra.Command, args []string) {
			logger := hclog.New(&hclog.LoggerOptions{
				Name:   "downloader",
				Output: os.Stdout,
				Level:  hclog.Debug,
			})
			downloader := DownloadPlugin{
				logger: logger,
			}
			err := downloader.Run(cmd, args)
			if err != nil {
				log.Fatal(err)
			}
		},
	}

	//agentCmd.Flags().StringP("source", string, "Directory or Bundle archive where policies are stored")
	//err := agentCmd.MarkFlagRequired("policy")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//agentCmd.Flags().StringArray("plugin", []string{}, "Plugin executable or directory")
	//agentCmd.MarkFlagsOneRequired("plugin")

	// --once run the agent once and not on a schedule. Right now this is default.
	// Actually run this as an agent on a schedule.

	return agentCmd
}

type DownloadPlugin struct {
	logger hclog.Logger

	queryBundles []*rego.Rego
}

func (d DownloadPlugin) Run(cmd *cobra.Command, args []string) error {
	fmt.Println("Running downloader")

	return nil
}
