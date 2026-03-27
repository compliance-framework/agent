package internal

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/hashicorp/go-hclog"
)

func TestDownload_FallsBackToExistingLocalDirectoryWhenNestedArtifactMissing(t *testing.T) {
	source := t.TempDir()

	got, err := Download(context.Background(), source, t.TempDir(), "policies", hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("Download() error = %v, expected nil", err)
	}

	if got != source {
		t.Fatalf("Download() = %q, expected %q", got, source)
	}
}

func TestDownload_UsesNestedArtifactForExistingLocalDirectory(t *testing.T) {
	source := t.TempDir()
	expected := filepath.Join(source, "plugin")

	if err := os.WriteFile(expected, []byte{}, 0o644); err != nil {
		t.Fatalf("os.WriteFile() error = %v, expected nil", err)
	}

	got, err := Download(context.Background(), source, t.TempDir(), "plugin", hclog.NewNullLogger())
	if err != nil {
		t.Fatalf("Download() error = %v, expected nil", err)
	}

	if got != expected {
		t.Fatalf("Download() = %q, expected %q", got, expected)
	}
}

func TestDownload_ReturnsErrorForLocalPluginDirectoryWithoutPlugin(t *testing.T) {
	source := t.TempDir()

	_, err := Download(context.Background(), source, t.TempDir(), "plugin", hclog.NewNullLogger())
	if err == nil {
		t.Fatal("Download() error = nil, expected error")
	}

	expected := "expected plugin executable at " + `"` + filepath.Join(source, "plugin") + `"`
	if err.Error() != expected {
		t.Fatalf("Download() error = %q, expected %q", err.Error(), expected)
	}
}

func TestDownload_SkipsOCIDownloadWhenExtractionPathExists(t *testing.T) {
	outputDir := t.TempDir()
	source := "ghcr.io/compliance-framework/plugin-test:v1"
	tag, err := name.NewTag(source)
	if err != nil {
		t.Fatalf("name.NewTag() error = %v, expected nil", err)
	}

	extractionPath := filepath.Join(outputDir, tag.RepositoryStr(), tag.Identifier())
	if err := os.MkdirAll(extractionPath, 0o755); err != nil {
		t.Fatalf("os.MkdirAll() error = %v, expected nil", err)
	}

	// Create a dummy plugin file to simulate an already extracted plugin.
	expected := filepath.Join(extractionPath, "plugin")
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

func TestDownload_SkipsOCIDownloadWhenPoliciesExtractionPathExists(t *testing.T) {
	outputDir := t.TempDir()
	source := "ghcr.io/compliance-framework/policy-test:v1"
	tag, err := name.NewTag(source)
	if err != nil {
		t.Fatalf("name.NewTag() error = %v, expected nil", err)
	}

	extractionPath := filepath.Join(outputDir, tag.RepositoryStr(), tag.Identifier())
	expected := filepath.Join(extractionPath, "policies")
	if err := os.MkdirAll(expected, 0o755); err != nil {
		t.Fatalf("os.MkdirAll() error = %v, expected nil", err)
	}

	got, err := Download(context.Background(), source, outputDir, "policies", hclog.NewNullLogger())
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
	if !info.IsDir() {
		t.Fatalf("Download() path %q is not a directory, expected a directory", got)
	}
}

func TestShouldSkipOCIDownload_ReturnsFalseWhenArtifactMissing(t *testing.T) {
	outputDir := t.TempDir()
	outDir := filepath.Join(outputDir, "ghcr.io", "compliance-framework", "plugin-test", "v1")
	localPath := filepath.Join(outDir, "plugin")

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("os.MkdirAll() error = %v, expected nil", err)
	}

	got, err := shouldSkipOCIDownload(outDir, localPath, "plugin")
	if err != nil {
		t.Fatalf("shouldSkipOCIDownload() error = %v, expected nil", err)
	}
	if got {
		t.Fatal("shouldSkipOCIDownload() = true, expected false when extracted artifact is missing")
	}
}

func TestShouldSkipOCIDownload_ReturnsErrorWhenExtractionPathIsNotDirectory(t *testing.T) {
	outputDir := t.TempDir()
	outDir := filepath.Join(outputDir, "ghcr.io", "compliance-framework", "plugin-test", "v1")
	localPath := filepath.Join(outDir, "plugin")

	if err := os.MkdirAll(filepath.Dir(outDir), 0o755); err != nil {
		t.Fatalf("os.MkdirAll() error = %v, expected nil", err)
	}
	if err := os.WriteFile(outDir, []byte{}, 0o644); err != nil {
		t.Fatalf("os.WriteFile() error = %v, expected nil", err)
	}

	got, err := shouldSkipOCIDownload(outDir, localPath, "plugin")
	if err == nil {
		t.Fatal("shouldSkipOCIDownload() error = nil, expected error")
	}
	if got {
		t.Fatal("shouldSkipOCIDownload() = true, expected false")
	}
}

func TestShouldSkipOCIDownload_ReturnsErrorWhenPoliciesPathIsFile(t *testing.T) {
	outputDir := t.TempDir()
	outDir := filepath.Join(outputDir, "ghcr.io", "compliance-framework", "policy-test", "v1")
	localPath := filepath.Join(outDir, "policies")

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("os.MkdirAll() error = %v, expected nil", err)
	}
	if err := os.WriteFile(localPath, []byte{}, 0o644); err != nil {
		t.Fatalf("os.WriteFile() error = %v, expected nil", err)
	}

	got, err := shouldSkipOCIDownload(outDir, localPath, "policies")
	if err == nil {
		t.Fatal("shouldSkipOCIDownload() error = nil, expected error")
	}
	if err.Error() != `expected extracted policies at "`+localPath+`" to be a directory` {
		t.Fatalf("shouldSkipOCIDownload() error = %q, expected %q", err.Error(), `expected extracted policies at "`+localPath+`" to be a directory`)
	}
	if got {
		t.Fatal("shouldSkipOCIDownload() = true, expected false")
	}
}
