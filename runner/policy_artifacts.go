package runner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/compliance-framework/api/sdk/types"
)

// Uploading policy artifacts: the policy bundle, input data and policy data a policy
// evaluation used. Plugins attach them to evidence as a PolicyEvaluation; the agent uploads
// them once per evaluation, sends the evidence with the digests the API returns, and never
// forwards the raw data. The API canonicalises and hashes; the agent only hashes locally to
// avoid re-uploading content it already sent.

const (
	artifactUploadAttempts = 3
	artifactCacheLimit     = 1024
	// After learning the API does not support artifacts, the agent stops trying for this
	// long, then checks again, so an API upgraded under a running agent is picked up.
	artifactsUnsupportedRecheck = 10 * time.Minute
)

// errArtifactsUnsupported means the API predates artifact storage.
var errArtifactsUnsupported = errors.New("the API does not support policy artifacts")

type artifactUploader struct {
	client      *sdk.Client
	policyPaths map[string]struct{}
	retryDelay  time.Duration

	mu               sync.Mutex
	uploaded         map[[sha256.Size]byte]string // local hash of uploaded bytes -> API digest
	unsupportedUntil time.Time
	now              func() time.Time
}

func newArtifactUploader(client *sdk.Client) *artifactUploader {
	return &artifactUploader{
		client:      client,
		policyPaths: map[string]struct{}{},
		retryDelay:  250 * time.Millisecond,
		uploaded:    map[[sha256.Size]byte]string{},
		now:         time.Now,
	}
}

// evaluationKey identifies an evaluation: by its stream Id when it has one, otherwise by
// what it depended on, since evidence from one evaluation sent in a batch arrives over gRPC
// as separate copies.
func evaluationKey(e *proto.PolicyEvaluation) string {
	if id := e.GetId(); id != "" {
		return "id:" + id
	}
	h := sha256.New()
	for _, part := range [][]byte{[]byte(e.GetPolicyPath()), e.GetInput(), e.GetPolicyData()} {
		_, _ = fmt.Fprintf(h, "%d:", len(part))
		_, _ = h.Write(part)
	}
	return "content:" + hex.EncodeToString(h.Sum(nil))
}

func (u *artifactUploader) storeEvaluation(ctx context.Context, evaluation *proto.PolicyEvaluation) (*types.PolicyArtifacts, error) {
	u.mu.Lock()
	unsupported := u.now().Before(u.unsupportedUntil)
	u.mu.Unlock()
	if unsupported {
		return nil, errArtifactsUnsupported
	}

	policyPath := filepath.Clean(evaluation.GetPolicyPath())
	if _, ok := u.policyPaths[policyPath]; !ok {
		return nil, fmt.Errorf("policy path %q is not one of the plugin's policy bundles", evaluation.GetPolicyPath())
	}
	if len(evaluation.GetInput()) == 0 {
		return nil, errors.New("the evaluation has no input data")
	}

	bundle, err := packageBundle(policyPath)
	if err != nil {
		return nil, fmt.Errorf("package policy bundle: %w", err)
	}

	refs := &types.PolicyArtifacts{}
	if refs.BundleDigest, err = u.upload(ctx, sdk.ArtifactMediaTypePolicyBundle, bundle); err != nil {
		return nil, fmt.Errorf("upload policy bundle: %w", err)
	}
	if refs.InputDigest, err = u.upload(ctx, sdk.ArtifactMediaTypeJSON, evaluation.GetInput()); err != nil {
		return nil, fmt.Errorf("upload input data: %w", err)
	}
	if len(evaluation.GetPolicyData()) > 0 {
		if refs.PolicyDataDigest, err = u.upload(ctx, sdk.ArtifactMediaTypeJSON, evaluation.GetPolicyData()); err != nil {
			return nil, fmt.Errorf("upload policy data: %w", err)
		}
	}
	return refs, nil
}

// upload stores content unless this agent already uploaded the same bytes, retrying
// temporary failures, and returns the digest the API assigned.
func (u *artifactUploader) upload(ctx context.Context, mediaType string, content []byte) (string, error) {
	local := sha256.Sum256(append([]byte(mediaType+"\x00"), content...))
	u.mu.Lock()
	digest, ok := u.uploaded[local]
	u.mu.Unlock()
	if ok {
		return digest, nil
	}

	var err error
	for attempt := 1; attempt <= artifactUploadAttempts; attempt++ {
		var info *sdk.ArtifactInfo
		info, err = u.client.Artifact.Upload(ctx, mediaType, content)
		if err == nil {
			u.remember(local, info.Digest)
			return info.Digest, nil
		}

		var statusErr *sdk.ArtifactStatusError
		if errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusNotFound || statusErr.StatusCode == http.StatusMethodNotAllowed) {
			u.mu.Lock()
			u.unsupportedUntil = u.now().Add(artifactsUnsupportedRecheck)
			u.mu.Unlock()
			return "", errArtifactsUnsupported
		}
		if !retryable(ctx, err) || attempt == artifactUploadAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return "", errors.Join(err, ctx.Err())
		case <-time.After(u.retryDelay * time.Duration(attempt)):
		}
	}
	return "", err
}

func (u *artifactUploader) remember(local [sha256.Size]byte, digest string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.uploaded) >= artifactCacheLimit {
		u.uploaded = map[[sha256.Size]byte]string{}
	}
	u.uploaded[local] = digest
}

// retryable reports whether an upload failure may succeed if repeated: server errors, rate
// limiting and transport errors. The API rejecting the content (4xx) is final.
func retryable(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var statusErr *sdk.ArtifactStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode >= 500 || statusErr.StatusCode == http.StatusTooManyRequests
	}
	return true
}

// packageBundle returns the policy bundle at policyPath for upload. A bundle archive, such as
// opa build's bundle.tar.gz used as a local policy, is sent as-is, since the API accepts a tar
// or gzipped tar; a directory, such as an extracted OCI policy, is archived.
func packageBundle(policyPath string) ([]byte, error) {
	info, err := os.Stat(policyPath)
	if err != nil {
		return nil, err
	}
	if info.Mode().IsRegular() {
		return os.ReadFile(policyPath)
	}
	return tarDirectory(policyPath)
}

// tarDirectory archives the regular files under dir. The API canonicalises the archive,
// so file order, modes and times here do not affect the digest.
func tarDirectory(dir string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", path)
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(content))}); err != nil {
			return err
		}
		_, err = tw.Write(content)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
