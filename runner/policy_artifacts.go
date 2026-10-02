package runner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/compliance-framework/agent/internal/policytree"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/compliance-framework/api/sdk/types"
)

// Uploading policy artifacts: the policy bundle, input data and policy data a policy
// evaluation used. Plugins attach them to evidence as a PolicyEvaluation; the agent uploads
// them once per evaluation, sends the evidence with the digests the API returns, and never
// forwards the raw data. The API canonicalises and hashes; the agent only hashes locally to
// avoid re-uploading content it already sent.
//
// The same artifact store is the agent's one channel for policy sources (R62): the
// reconciler uploads the policy trees it reports, through the same ArtifactUploader, so a
// tree uploaded at configuration time is not uploaded again at evaluation time.

const (
	artifactUploadAttempts = 3
	artifactCacheLimit     = 1024
	// After learning the API does not support artifacts, the agent stops trying for this
	// long, then checks again, so an API upgraded under a running agent is picked up.
	artifactsUnsupportedRecheck = 10 * time.Minute
)

// ErrArtifactsUnsupported means the API predates artifact storage.
var ErrArtifactsUnsupported = errors.New("the API does not support policy artifacts")

// ArtifactClient is the artifact route of one API (sdk.Client.Artifact).
type ArtifactClient interface {
	Upload(ctx context.Context, mediaType string, content []byte) (*sdk.ArtifactInfo, error)
}

// ArtifactUploader uploads artifacts for the whole agent process: the reconciler and the API
// helper of every plugin run share one, so content is uploaded once per API whoever needs
// it first. It remembers what each API already has (by a local hash of the bytes), retries
// temporary failures, and backs off from an API that predates artifact storage. It is safe
// for concurrent use.
type ArtifactUploader struct {
	retryDelay time.Duration
	now        func() time.Time

	mu               sync.Mutex
	uploaded         map[artifactKey]string // what each API already has -> its digest
	unsupportedUntil map[string]time.Time   // per API
}

type artifactKey struct {
	api   string
	local [sha256.Size]byte
}

// NewArtifactUploader returns an empty uploader.
func NewArtifactUploader() *ArtifactUploader {
	return &ArtifactUploader{
		retryDelay:       250 * time.Millisecond,
		now:              time.Now,
		uploaded:         map[artifactKey]string{},
		unsupportedUntil: map[string]time.Time{},
	}
}

// Endpoint binds the uploader to one API: api identifies it (its base URL) and client is its
// artifact route. Endpoints of the same api share what was uploaded.
func (u *ArtifactUploader) Endpoint(api string, client ArtifactClient) *ArtifactEndpoint {
	return &ArtifactEndpoint{u: u, api: api, client: client}
}

// ArtifactEndpoint uploads to one API through a shared ArtifactUploader.
type ArtifactEndpoint struct {
	u      *ArtifactUploader
	api    string
	client ArtifactClient
}

// unsupported reports whether the API was found not to support artifacts recently.
func (e *ArtifactEndpoint) unsupported() bool {
	e.u.mu.Lock()
	defer e.u.mu.Unlock()
	return e.u.now().Before(e.u.unsupportedUntil[e.api])
}

// Upload stores content unless this agent already uploaded the same bytes to this API,
// retrying temporary failures, and returns the digest the API assigned. A 404 or 405 means
// the API predates artifacts: ErrArtifactsUnsupported, and no upload to it is attempted for
// a while. Other failures are returned as they are (*sdk.ArtifactStatusError for a status).
func (e *ArtifactEndpoint) Upload(ctx context.Context, mediaType string, content []byte) (string, error) {
	u := e.u
	key := artifactKey{api: e.api, local: sha256.Sum256(append([]byte(mediaType+"\x00"), content...))}
	u.mu.Lock()
	digest, ok := u.uploaded[key]
	unsupported := u.now().Before(u.unsupportedUntil[e.api])
	u.mu.Unlock()
	if ok {
		return digest, nil
	}
	if unsupported {
		return "", ErrArtifactsUnsupported
	}
	if e.client == nil {
		return "", errors.New("no API client")
	}

	var err error
	for attempt := 1; attempt <= artifactUploadAttempts; attempt++ {
		var info *sdk.ArtifactInfo
		info, err = e.client.Upload(ctx, mediaType, content)
		if err == nil {
			u.remember(key, info.Digest)
			return info.Digest, nil
		}

		var statusErr *sdk.ArtifactStatusError
		if errors.As(err, &statusErr) && (statusErr.StatusCode == http.StatusNotFound || statusErr.StatusCode == http.StatusMethodNotAllowed) {
			u.mu.Lock()
			u.unsupportedUntil[e.api] = u.now().Add(artifactsUnsupportedRecheck)
			u.mu.Unlock()
			return "", ErrArtifactsUnsupported
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

func (u *ArtifactUploader) remember(key artifactKey, digest string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.uploaded) >= artifactCacheLimit {
		u.uploaded = map[artifactKey]string{}
	}
	u.uploaded[key] = digest
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

// storeEvaluation uploads what one evaluation used: the policy bundle at the policy path the
// plugin was given (see WithPolicyPaths), its input and its policy data.
func (h *apiHelper) storeEvaluation(ctx context.Context, evaluation *proto.PolicyEvaluation) (*types.PolicyArtifacts, error) {
	if h.artifacts.unsupported() {
		return nil, ErrArtifactsUnsupported
	}
	policyPath := filepath.Clean(evaluation.GetPolicyPath())
	if _, ok := h.policyPaths[policyPath]; !ok {
		return nil, fmt.Errorf("policy path %q is not one of the plugin's policy bundles", evaluation.GetPolicyPath())
	}
	if len(evaluation.GetInput()) == 0 {
		return nil, errors.New("the evaluation has no input data")
	}

	bundle, err := policytree.TarDirectory(policyPath)
	if err != nil {
		return nil, fmt.Errorf("package policy bundle: %w", err)
	}

	refs := &types.PolicyArtifacts{}
	if refs.BundleDigest, err = h.artifacts.Upload(ctx, sdk.ArtifactMediaTypePolicyBundle, bundle); err != nil {
		return nil, fmt.Errorf("upload policy bundle: %w", err)
	}
	if refs.InputDigest, err = h.artifacts.Upload(ctx, sdk.ArtifactMediaTypeJSON, evaluation.GetInput()); err != nil {
		return nil, fmt.Errorf("upload input data: %w", err)
	}
	if len(evaluation.GetPolicyData()) > 0 {
		if refs.PolicyDataDigest, err = h.artifacts.Upload(ctx, sdk.ArtifactMediaTypeJSON, evaluation.GetPolicyData()); err != nil {
			return nil, fmt.Errorf("upload policy data: %w", err)
		}
	}
	return refs, nil
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
