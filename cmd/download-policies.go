package cmd

import (
	"context"
	"os"
	"path/filepath"

	"github.com/compliance-framework/agent/internal"
	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
)

func DownloadPolicyCmd() *cobra.Command {
	var policyCmd = &cobra.Command{
		Use:   "download-policy",
		Short: "downloads policies from OCI or URLs",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := hclog.New(&hclog.LoggerOptions{
				Output: os.Stdout,
				Level:  hclog.Debug,
			})
			downloadCmd := PolicyDownloadRunner{
				logger: logger,
			}
			return downloadCmd.Run(cmd, args)
		},
	}

	var source []string
	policyCmd.Flags().StringArrayVarP(&source, "source", "s", source, "OCI or URL sources of the policies")
	policyCmd.MarkFlagsOneRequired("source")

	return policyCmd
}

type PolicyDownloadRunner struct {
	logger hclog.Logger
}

func (d *PolicyDownloadRunner) Run(cmd *cobra.Command, args []string) error {
	sources, err := cmd.Flags().GetStringArray("source")
	if err != nil {
		return err
	}

	basePath, loopErr := os.Getwd()
	if loopErr != nil {
		return loopErr
	}

	policyPath := filepath.Join(basePath, AgentPolicyDir)

	for _, source := range sources {
		d.logger.Debug("Received source", "source", source)

		if internal.IsOCI(source) {
			location, err := internal.Download(context.Background(), source, policyPath, "policies", d.logger)
			if err != nil {
				return err
			}

			d.logger.Debug("Policy available locally", "path", location)
		}
	}

	return nil
}
