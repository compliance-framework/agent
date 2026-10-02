package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/compliance-framework/agent/internal/policytree"
	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/sdk"
)

func tarDigest(t *testing.T, dir string) string {
	t.Helper()
	tarball, err := policytree.TarDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tarball)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// vendorBaseConfig runs plugin ssh with the OCI policy source ghcr.io/vendor/policies:v1.
const vendorBaseConfig = `
daemon: true
api:
  url: http://api.test
  auth:
    client_id: 123e4567-e89b-12d3-a456-426614174000
    client_secret: s3cret
remote_config:
  mode: apply_safe
plugins:
  ssh:
    source: ghcr.io/compliance-framework/plugin-ssh:v1
    policies: ["ghcr.io/vendor/policies:v1"]
`

// newVendorHarness is a remote harness on config whose policy resolver serves
// ghcr.io/vendor/policies:v1 from a temporary tree, which it returns.
func newVendorHarness(t *testing.T, config string) (*remoteHarness, string) {
	t.Helper()
	vendor := t.TempDir()
	if err := os.WriteFile(filepath.Join(vendor, "banner.rego"), []byte("package compliance_framework.banner\n\nimport rego.v1\n\nviolation contains {\"remarks\": \"b\"} if not input.banner\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newRemoteHarness(t, config)
	h.rc.resolvePolicy = func(_ context.Context, source string) (string, error) {
		if source == "ghcr.io/vendor/policies:v1" {
			return vendor, nil
		}
		return "", errors.New("unknown source " + source)
	}
	return h, vendor
}

// TestArtifacts_ReportNamesTheSources_R62: the report inventories the policy source and
// carries the artifact digest of its tree, the digest a plugin's evaluation-time upload of
// the same directory produces.
func TestArtifacts_ReportNamesTheSources_R62(t *testing.T) {
	h, vendor := newVendorHarness(t, vendorBaseConfig)
	active := mustStartup(t, h.rc)

	r := h.remote.lastReport(t)
	if len(r.PolicyBundles) != 1 {
		t.Fatalf("unexpected policy-bundles %+v", r.PolicyBundles)
	}
	b := r.PolicyBundles[0]
	if b.Source != "ghcr.io/vendor/policies:v1" || len(b.Files) != 1 || b.Files[0].Path != "banner.rego" || b.Files[0].Package != "compliance_framework.banner" {
		t.Fatalf("unexpected inventory %+v", b)
	}
	if want := tarDigest(t, vendor); b.ArtifactDigest != want {
		t.Fatalf("artifact-digest = %q, want %q", b.ArtifactDigest, want)
	}
	if n := h.remote.uploadCount(); n != 1 {
		t.Fatalf("expected one upload per tree, got %d", n)
	}

	// Memoized: later reports upload nothing.
	h.clock.Advance(reportResendInterval + 1)
	h.rc.maybeReport(context.Background(), active, nil)
	if n := h.remote.uploadCount(); n != 1 {
		t.Fatalf("trees must be uploaded once, got %d uploads", n)
	}

	// The digests survive dropping the file lists to fit the report size.
	_, _, err := fitReport(&r, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.PolicyBundles[0].Files) != 0 || r.PolicyBundles[0].ArtifactDigest != b.ArtifactDigest {
		t.Fatalf("truncation must keep artifact-digest: %+v", r.PolicyBundles[0])
	}
}

func TestArtifacts_SourcesAreUploaded(t *testing.T) {
	local := t.TempDir()
	if err := os.WriteFile(filepath.Join(local, "p.rego"), []byte("package compliance_framework.p\n\ntitle := \"p\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newRemoteHarness(t, strings.Replace(vendorBaseConfig, `policies: ["ghcr.io/vendor/policies:v1"]`, `policies: ["ghcr.io/vendor/policies:v1", "`+local+`"]`, 1))
	h.rc.resolvePolicy = func(_ context.Context, source string) (string, error) {
		switch source {
		case "ghcr.io/vendor/policies:v1":
			return local, nil
		case local:
			return local, nil
		}
		return "", errors.New("unknown source " + source)
	}
	mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	var found bool
	for _, b := range r.PolicyBundles {
		if b.Source == local {
			found = true
			if want := tarDigest(t, local); b.ArtifactDigest != want {
				t.Fatalf("local source artifact-digest = %q, want %q", b.ArtifactDigest, want)
			}
		}
	}
	if !found {
		t.Fatalf("the local source is not reported: %+v", r.PolicyBundles)
	}
}

// TestArtifacts_FailuresNeverRejectOrFail: an upload failure leaves artifact-digest empty;
// the revision applies, and a refused tree is not retried.
func TestArtifacts_FailuresNeverRejectOrFail(t *testing.T) {
	for name, tc := range map[string]struct {
		err         error
		wantRetried bool
	}{
		"old API":         {err: runner.ErrArtifactsUnsupported},
		"too large":       {err: &sdk.ArtifactStatusError{StatusCode: http.StatusRequestEntityTooLarge}},
		"invalid":         {err: &sdk.ArtifactStatusError{StatusCode: http.StatusBadRequest}},
		"rate limited":    {err: &sdk.ArtifactStatusError{StatusCode: http.StatusTooManyRequests}, wantRetried: true},
		"transport error": {err: errors.New("connection reset"), wantRetried: true},
		"timeout":         {err: context.DeadlineExceeded, wantRetried: true},
	} {
		t.Run(name, func(t *testing.T) {
			h, _ := newVendorHarness(t, vendorBaseConfig)
			failing := true
			h.remote.uploadErr = func(int) error {
				if failing {
					return tc.err
				}
				return nil
			}
			active := mustStartup(t, h.rc)
			r := h.remote.lastReport(t)
			if r.Status == agentconfig.StatusRejected || r.Status == agentconfig.StatusFailed {
				t.Fatalf("an artifact failure must not reject or fail: %s/%s", r.Status, r.Reason)
			}
			if r.PolicyBundles[0].ArtifactDigest != "" {
				t.Fatalf("a failed upload must leave artifact-digest empty: %+v", r.PolicyBundles[0])
			}

			failing = false
			before := h.remote.uploadCount()
			h.clock.Advance(reportResendInterval + 1)
			h.rc.maybeReport(context.Background(), active, nil)
			retried := h.remote.uploadCount() > before
			if errors.Is(tc.err, runner.ErrArtifactsUnsupported) {
				// The shared uploader owns the old-API backoff; the reconciler retries on
				// the next report and the uploader answers without a request.
				return
			}
			if retried != tc.wantRetried {
				t.Fatalf("retried = %v, want %v", retried, tc.wantRetried)
			}
			if tc.wantRetried && h.remote.lastReport(t).PolicyBundles[0].ArtifactDigest == "" {
				t.Fatal("a retried upload must fill artifact-digest")
			}
		})
	}
}

// TestArtifacts_ModeOffUploadsNothing: no report, no upload.
func TestArtifacts_ModeOffUploadsNothing(t *testing.T) {
	h, _ := newVendorHarness(t, strings.Replace(vendorBaseConfig, "mode: apply_safe", `mode: "off"`, 1))
	mustStartup(t, h.rc)
	if n := h.remote.uploadCount(); n != 0 {
		t.Fatalf("mode off must not upload, got %d", n)
	}
}

// TestReport_PluginsCarryTheirLibVersion_R76: the report lists every plugin with the agent
// library its binary was built with; a version that cannot be read is reported as unknown.
func TestReport_PluginsCarryTheirLibVersion_R76(t *testing.T) {
	config := vendorBaseConfig + `  aws:
    source: ghcr.io/compliance-framework/plugin-aws:v1
`
	h, _ := newVendorHarness(t, config)
	h.rc.pluginLib = func(_ context.Context, source string) (string, error) {
		if source == "ghcr.io/compliance-framework/plugin-ssh:v1" {
			return "v0.7.1", nil
		}
		return "", errors.New("not a Go binary")
	}
	mustStartup(t, h.rc)
	got := h.remote.lastReport(t).Plugins
	want := []agentconfig.PluginReport{
		{Name: "aws", Source: "ghcr.io/compliance-framework/plugin-aws:v1"},
		{Name: "ssh", Source: "ghcr.io/compliance-framework/plugin-ssh:v1", LibVersion: "v0.7.1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plugins = %+v, want %+v", got, want)
	}
}

// TestArtifacts_SharedUploaderDedupesWithEvaluation: the reconciler and a plugin's API
// helper share the process-wide uploader, so a tree the reconciler uploaded is not uploaded
// again when the plugin's evidence references it.
func TestArtifacts_SharedUploaderDedupesWithEvaluation(t *testing.T) {
	var uploads int
	client := &countingArtifacts{n: &uploads}
	shared := runner.NewArtifactUploader()
	remote := sdkRemote{artifacts: shared.Endpoint("http://api.test", client)}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.rego"), []byte("package compliance_framework.p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tarball, err := policytree.TarDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := remote.UploadArtifact(context.Background(), sdk.ArtifactMediaTypePolicyBundle, tarball); err != nil {
			t.Fatal(err)
		}
		if _, err := shared.Endpoint("http://api.test", client).Upload(context.Background(), sdk.ArtifactMediaTypePolicyBundle, tarball); err != nil {
			t.Fatal(err)
		}
	}
	if uploads != 1 {
		t.Fatalf("expected one upload, got %d", uploads)
	}
}

type countingArtifacts struct{ n *int }

func (c *countingArtifacts) Upload(_ context.Context, mediaType string, content []byte) (*sdk.ArtifactInfo, error) {
	*c.n++
	sum := sha256.Sum256(content)
	return &sdk.ArtifactInfo{Digest: "sha256:" + hex.EncodeToString(sum[:]), MediaType: mediaType}, nil
}
