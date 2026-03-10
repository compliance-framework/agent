package internal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path"

	"github.com/compliance-framework/gooci/pkg/oci"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
)

func IsOCI(source string) bool {
	// Check whether this can be parsed as an OCI endpoint
	_, err := name.NewTag(source, name.StrictValidation)
	return err == nil
}

func GetAnnotations(source string, option ...remote.Option) (map[string]string, error) {
	ref, err := name.ParseReference(source)
	if err != nil {
		return nil, err
	}

	opts := append([]remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}, option...)

	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return nil, err
	}

	return annotationsFromDescriptor(desc), nil
}

func annotationsFromDescriptor(desc *remote.Descriptor) map[string]string {
	if desc == nil {
		return map[string]string{}
	}

	if len(desc.Manifest) > 0 {
		var payload struct {
			Annotations map[string]string `json:"annotations"`
		}

		if err := json.Unmarshal(desc.Manifest, &payload); err == nil && len(payload.Annotations) > 0 {
			return payload.Annotations
		}
	}

	if len(desc.Annotations) > 0 {
		return desc.Annotations
	}

	return map[string]string{}
}

func Download(ctx context.Context, source string, outputDir string, binaryPath string, logger hclog.Logger, option ...remote.Option) (string, error) {
	// Add a task to indicate we've downloaded the items
	logger.Trace("Checking for source", "source", source)

	// First we check if the source is a path that exists on the fs, if so we just use that.
	_, err := os.ReadFile(source)

	if err == nil {
		// The file exists. Just return it.
		logger.Debug("Found source locally, using local file", "File", source)

		// The file exists locally, so we use the local path.
		return source, nil
	}

	// The error we've received is something other than not exists.
	// Exit early with the error
	if !os.IsNotExist(err) {
		return "", err
	}

	if IsOCI(source) {
		logger.Debug("Source looks like an OCI endpoint, attempting to download", "Source", source)
		tag, err := name.NewTag(source)
		if err != nil {
			return "", err
		}

		outDir := path.Join(outputDir, tag.RepositoryStr(), tag.Identifier())

		downloaderImpl, err := oci.NewDownloader(
			tag,
			outDir,
		)
		if err != nil {
			return "", err
		}
		err = downloaderImpl.Download(option...)
		if err != nil {
			return "", err
		}

		return path.Join(outDir, binaryPath), nil
	}

	return "", errors.New("downloadable item source cannot be found locally and does not look like OCI")
}
