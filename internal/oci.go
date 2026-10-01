package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/compliance-framework/gooci/pkg/oci"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
)

func IsOCI(source string) bool {
	// Check whether this can be parsed as an OCI tag, which is what our downloader supports.
	_, err := name.NewTag(source, name.StrictValidation)
	return err == nil
}

func GetAnnotations(ctx context.Context, source string, option ...remote.Option) (map[string]string, error) {
	ref, err := name.ParseReference(source, name.StrictValidation)
	if err != nil {
		return nil, err
	}

	opts := append([]remote.Option{
		remote.WithContext(ctx),
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
			return copyAnnotations(payload.Annotations)
		}
	}

	if len(desc.Annotations) > 0 {
		return copyAnnotations(desc.Annotations)
	}

	return map[string]string{}
}

func copyAnnotations(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}

	return out
}

func shouldSkipOCIDownload(outDir string, localPath string, binaryPath string) (bool, error) {
	outDirInfo, err := os.Stat(outDir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !outDirInfo.IsDir() {
		return false, fmt.Errorf("OCI extraction path %q exists but is not a directory", outDir)
	}

	localPathInfo, err := os.Stat(localPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	switch binaryPath {
	case "plugin":
		if localPathInfo.IsDir() {
			return false, fmt.Errorf("expected extracted plugin at %q to be a file", localPath)
		}
	case "policies":
		if !localPathInfo.IsDir() {
			return false, fmt.Errorf("expected extracted policies at %q to be a directory", localPath)
		}
	default:
		return false, fmt.Errorf("unsupported extracted artifact %q", binaryPath)
	}

	return true, nil
}

func Download(ctx context.Context, source string, outputDir string, binaryPath string, logger hclog.Logger, option ...remote.Option) (string, error) {
	// Add a task to indicate we've downloaded the items
	logger.Trace("Checking for source", "source", source)

	// First we check if the source is a path that exists on the fs, if so we just use that.
	sourceInfo, err := os.Stat(source)

	if err == nil {
		if sourceInfo.IsDir() {
			localPath := filepath.Join(source, binaryPath)
			useNestedPath, err := shouldSkipOCIDownload(source, localPath, binaryPath)
			if err != nil {
				return "", err
			}
			if useNestedPath {
				logger.Debug("Found source locally, using extracted artifact path", "Path", localPath)
				return localPath, nil
			}
			if binaryPath == "plugin" {
				return "", fmt.Errorf("expected plugin executable at %q", localPath)
			}
		}

		// The file exists. Just return it.
		logger.Debug("Found source locally, using local path", "Path", source)

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

		outDir := filepath.Join(outputDir, tag.RepositoryStr(), tag.Identifier())
		localPath := filepath.Join(outDir, binaryPath)

		skipDownload, err := shouldSkipOCIDownload(outDir, localPath, binaryPath)
		if err != nil {
			return "", err
		}
		if skipDownload {
			logger.Debug("OCI extraction path already exists, skipping download", "Source", source, "Path", outDir)
			return localPath, nil
		}

		// The registry digest the tag resolves to, recorded next to the extracted files so
		// later runs, which skip the download, still know exactly what they run.
		descriptor, headErr := remote.Head(tag, append([]remote.Option{remote.WithAuthFromKeychain(oci.ECRKeychain())}, option...)...)
		if headErr != nil {
			logger.Warn("Could not resolve the registry digest; evidence will not record it", "source", source, "error", headErr)
		}

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

		if descriptor != nil {
			if err := writeSourceRecord(outDir, source, descriptor.Digest.String()); err != nil {
				logger.Warn("Could not record the registry digest; evidence will not record it", "source", source, "error", err)
			}
		}

		return localPath, nil
	}

	return "", errors.New("downloadable item source cannot be found locally and does not look like OCI")
}

// sourceRecordFile is written next to an OCI artifact's extracted files when the agent
// downloads it, recording the registry digest its tag resolved to.
const sourceRecordFile = ".ccf-source.json"

type sourceRecord struct {
	Reference string `json:"reference"`
	Digest    string `json:"digest"`
}

func writeSourceRecord(outDir, reference, digest string) error {
	record, err := json.Marshal(sourceRecord{Reference: reference, Digest: digest})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, sourceRecordFile), record, 0o644)
}

// SourceDigest returns the digest of what the agent runs from source, extracted at
// localPath. For an OCI source it is the registry digest recorded when the agent downloaded
// it, or "" for files extracted before digests were recorded. For a local file, such as a
// plugin binary, it is the file's SHA-256. Otherwise it is "".
func SourceDigest(source, localPath string) string {
	if IsOCI(source) {
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(localPath), sourceRecordFile))
		if err != nil {
			return ""
		}
		var record sourceRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return ""
		}
		return record.Digest
	}

	info, err := os.Stat(localPath)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(localPath)
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return ""
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
