package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/compliance-framework/agent/internal/policytree"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/sdk"
)

// Policy sources through the artifact store (R62). The report names every policy tree the
// agent runs (inline bundles, the vendor trees they extend, OCI and local sources) by tree
// digest. The agent also uploads each tree as a policy bundle artifact, through the same
// process-wide uploader the plugins' evidence uses, and reports the artifact digest next to
// the tree digest, so the UI can read the sources (GET /api/artifacts/{digest}/files).
//
// Uploads are best effort: a failure leaves artifact-digest empty and never rejects or fails
// a revision. They happen at report time, so only in report and apply modes, only for the
// candidate that runs (its checks passed), within remoteRequestTimeout per report.

// artifactMemoLimit bounds the tree digest -> artifact digest memo.
const artifactMemoLimit = 1024

// artifactDigestPattern is the format of an artifact digest (the API checks the same).
var artifactDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// errTreeChanged: a local tree no longer has the digest it was inventoried with.
var errTreeChanged = errors.New("the policy tree changed since it was inventoried")

// artifactTree is a policy tree the report names, and the directory it was read from.
type artifactTree struct {
	digest string // agentconfig.BundleTreeDigest of the tree
	dir    string
}

// uploadArtifacts uploads the trees of c that have no artifact yet. Each tree is uploaded
// once per process (memoized by tree digest); a tree the API refused for good is not retried.
func (rc *reconciler) uploadArtifacts(ctx context.Context, c *candidate) {
	if rc.remote == nil || c == nil || len(c.trees) == 0 {
		return
	}
	var pending []artifactTree
	for _, t := range c.trees {
		if _, done := rc.artifactMemo[t.digest]; !done && t.dir != "" {
			pending = append(pending, t)
		}
	}
	if len(pending) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, remoteRequestTimeout)
	defer cancel()
	for _, t := range pending {
		if _, done := rc.artifactMemo[t.digest]; done {
			continue // the same tree twice in c
		}
		digest, err := rc.uploadTree(ctx, t)
		var statusErr *sdk.ArtifactStatusError
		switch {
		case err == nil:
			rc.rememberArtifact(t.digest, digest)
		case errors.Is(err, runner.ErrArtifactsUnsupported):
			if rc.logOnce("artifacts:unsupported") {
				rc.logger.Info("The API does not support policy artifacts; the report names policy trees without their sources")
			}
			return
		case ctx.Err() != nil:
			if rc.logOnce("artifacts:timeout") {
				rc.logger.Warn("Uploading policy trees as artifacts timed out; retrying with the next report", "timeout", remoteRequestTimeout)
			}
			return
		case errors.Is(err, errTreeChanged):
			// The candidate's report is stale for this tree; do not re-read it every poll.
			rc.rememberArtifact(t.digest, "")
			if rc.logOnce("artifacts:" + t.digest) {
				rc.logger.Warn("A policy tree changed on disk since it was inventoried; the report names it without its sources", "dir", t.dir, "error", err)
			}
		case errors.As(err, &statusErr) && permanentArtifactFailure(statusErr.StatusCode):
			rc.rememberArtifact(t.digest, "")
			if rc.logOnce("artifacts:" + t.digest) {
				rc.logger.Warn("The API refused a policy tree artifact; the report names it without its sources", "tree", t.digest, "status", statusErr.StatusCode, "error", err)
			}
		default:
			if rc.logOnce("artifacts:" + t.digest) {
				rc.logger.Warn("Could not upload a policy tree artifact; retrying with the next report", "tree", t.digest, "error", err)
			}
		}
	}
}

// uploadTree archives t exactly as the plugins' API helper archives a policy path, so both
// get the same artifact. A tree that changed on disk since it was inventoried (a local
// source edited in place) is not uploaded under the old digest.
func (rc *reconciler) uploadTree(ctx context.Context, t artifactTree) (string, error) {
	files, _, err := policytree.ReadTree(t.dir)
	if err != nil {
		return "", err
	}
	if got := agentconfig.BundleTreeDigest(files); got != t.digest {
		return "", fmt.Errorf("%w: %s was %s, now %s", errTreeChanged, t.dir, t.digest, got)
	}
	tarball, err := policytree.TarFiles(files)
	if err != nil {
		return "", err
	}
	digest, err := rc.remote.UploadArtifact(ctx, sdk.ArtifactMediaTypePolicyBundle, tarball)
	if err != nil {
		return "", err
	}
	if !artifactDigestPattern.MatchString(digest) {
		return "", fmt.Errorf("the API returned an invalid artifact digest %q", digest)
	}
	return digest, nil
}

// permanentArtifactFailure reports whether an upload status means the API will never take
// this content (too large, invalid). 404/405 (no artifact support), 408 and 429 are not.
func permanentArtifactFailure(status int) bool {
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return status >= 400 && status < 500
}

func (rc *reconciler) rememberArtifact(tree, artifact string) {
	if len(rc.artifactMemo) >= artifactMemoLimit {
		rc.artifactMemo = map[string]string{}
	}
	rc.artifactMemo[tree] = artifact
}

// withArtifactDigests returns bundles with the artifact digests known for their trees. It
// copies what it changes: the candidate's reports are shared.
func (rc *reconciler) withArtifactDigests(bundles []agentconfig.PolicyBundleReport) []agentconfig.PolicyBundleReport {
	out := append([]agentconfig.PolicyBundleReport(nil), bundles...)
	for i := range out {
		out[i].ArtifactDigest = rc.artifactMemo[out[i].Digest]
		if out[i].Extends != nil {
			ext := *out[i].Extends
			ext.ArtifactDigest = rc.artifactMemo[ext.Digest]
			out[i].Extends = &ext
		}
	}
	return out
}
