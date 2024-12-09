package cmd

import (
	"os"
	"path"

	"github.com/chris-cmsoft/concom/internal"
	"github.com/compliance-framework/gooci/pkg/oci"
	"github.com/google/go-containerregistry/pkg/name"
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

	policyPath := path.Join(basePath, AgentPolicyDir)

	for _, source := range sources {
		d.logger.Debug("Received source", "source", source)

		if internal.IsOCI(source) {
			tag, err := name.NewTag(source)
			if err != nil {
				return err
			}
			destination := path.Join(policyPath, tag.RepositoryStr(), tag.Identifier())
			downloaderImpl, err := oci.NewDownloader(
				tag,
				destination,
			)
			if err != nil {
				return err
			}
			err = downloaderImpl.Download()
			if err != nil {
				return err
			}

			d.logger.Debug("Downloaded policy", "path", destination)
		}
	}

	return nil
}
