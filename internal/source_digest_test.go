package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pushTestImage pushes a random image to an in-memory registry and returns its reference and
// registry digest.
func pushTestImage(t *testing.T) (string, string) {
	t.Helper()
	server := httptest.NewServer(registry.New())
	t.Cleanup(server.Close)
	u, err := url.Parse(server.URL)
	require.NoError(t, err)

	image, err := random.Image(256, 1)
	require.NoError(t, err)
	reference := u.Host + "/compliance-framework/test-policies:v1.0.0"
	tag, err := name.NewTag(reference)
	require.NoError(t, err)
	require.NoError(t, remote.Write(tag, image))

	digest, err := image.Digest()
	require.NoError(t, err)
	return reference, digest.String()
}

func TestDownloadRecordsTheRegistryDigest(t *testing.T) {
	reference, digest := pushTestImage(t)
	outputDir := t.TempDir()

	localPath, err := Download(context.Background(), reference, outputDir, "policies", hclog.NewNullLogger())
	require.NoError(t, err)
	assert.Equal(t, digest, SourceDigest(reference, localPath))

	// A later run finds the files extracted, skips the download, and still knows the digest.
	require.NoError(t, os.MkdirAll(localPath, 0o755))
	again, err := Download(context.Background(), reference, outputDir, "policies", hclog.NewNullLogger())
	require.NoError(t, err)
	assert.Equal(t, localPath, again)
	assert.Equal(t, digest, SourceDigest(reference, again))
}

func TestSourceDigestForAnExtractionWithoutARecord(t *testing.T) {
	// As left by agents from before digests were recorded.
	localPath := filepath.Join(t.TempDir(), "ghcr.io", "org", "policies", "v1", "policies")
	require.NoError(t, os.MkdirAll(localPath, 0o755))
	assert.Empty(t, SourceDigest("ghcr.io/org/policies:v1", localPath))
}

func TestSourceDigestForLocalSources(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "plugin")
	require.NoError(t, os.WriteFile(binary, []byte("plugin binary"), 0o755))
	sum := sha256.Sum256([]byte("plugin binary"))

	assert.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), SourceDigest(binary, binary), "a local plugin binary is hashed")
	assert.Empty(t, SourceDigest(dir, dir), "a local policy directory has no digest")
	assert.Empty(t, SourceDigest(filepath.Join(dir, "missing"), filepath.Join(dir, "missing")))
}
