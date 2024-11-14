package cmd

import (
	"fmt"
	"github.com/chris-cmsoft/concom/internal/downloader"
	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
	"log"
	"os"
	"path"
)

func DownloadPluginCmd() *cobra.Command {
	var agentCmd = &cobra.Command{
		Use:   "download-plugin",
		Short: "downloads plugins from OCI or URLs",
		Run: func(cmd *cobra.Command, args []string) {
			logger := hclog.New(&hclog.LoggerOptions{
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

	var source []string
	agentCmd.Flags().StringArrayVarP(&source, "source", "s", source, "OCI or URL sources of the plugins")
	agentCmd.MarkFlagsOneRequired("source")

	return agentCmd
}

type DownloadPlugin struct {
	logger hclog.Logger
}

func (d DownloadPlugin) Run(cmd *cobra.Command, args []string) error {
	fmt.Println("Running downloader")

	sources, err := cmd.Flags().GetStringArray("source")
	if err != nil {
		return err
	}

	for _, source := range sources {
		d.logger.Debug("Received source", "source", source)

		basePath, err := os.Getwd()
		if err != nil {
			return err
		}
		err = downloader.Download(source, path.Join(basePath, ".compliance-framework/plugins/"))
		if err != nil {
			return err
		}
	}

	return nil
}
