package internal

import (
	"context"
	"os"
	"path"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-hclog"
)

func TestDownload_UsesExistingLocalDirectory(t *testing.T) {
	source := t.TempDir()

	got, err := Download(context.Background(), source, t.TempDir(), "policies", hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("Download() error = %v, expected nil", err)
	}

	if got != source {
		t.Fatalf("Download() = %q, expected %q", got, source)
	}
}

func TestDownload_SkipsOCIDownloadWhenExtractionPathExists(t *testing.T) {
	outputDir := t.TempDir()
	source := "ghcr.io/compliance-framework/plugin-test:v1"
	tag, err := name.NewTag(source)
	if err != nil {
		t.Fatalf("name.NewTag() error = %v, expected nil", err)
	}

	extractionPath := path.Join(outputDir, tag.RepositoryStr(), tag.Identifier())
	if err := os.MkdirAll(extractionPath, 0o755); err != nil {
		t.Fatalf("os.MkdirAll() error = %v, expected nil", err)
	}

	// Create a dummy plugin file to simulate an already extracted plugin.
	expected := path.Join(extractionPath, "plugin")
	if err := os.WriteFile(expected, []byte{}, 0o644); err != nil {
		t.Fatalf("os.WriteFile() error = %v, expected nil", err)
	}

	got, err := Download(context.Background(), source, outputDir, "plugin", hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("Download() error = %v, expected nil", err)
	}

	if got != expected {
		t.Fatalf("Download() = %q, expected %q", got, expected)
	}

	info, err := os.Stat(got)
	if err != nil {
		t.Fatalf("os.Stat() error = %v, expected nil", err)
	}
	if info.IsDir() {
		t.Fatalf("Download() path %q is a directory, expected a file", got)
	}
}
