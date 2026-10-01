package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
)

const inlineBaseConfig = `
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
    policies: ["inline:ssh"]
    policy_data:
      max: 3
policy_bundles:
  ssh:
    extends: ghcr.io/vendor/policies:v1
    modules:
      extra.rego: |
        package compliance_framework.extra

        import rego.v1

        title := "extra"

        violation contains {"remarks": "x"} if input.max > data.max
`

func newInlineHarness(t *testing.T) (*remoteHarness, string) {
	t.Helper()
	return newInlineHarnessWith(t, inlineBaseConfig)
}

// newInlineHarnessWith is newInlineHarness on config, which may use the vendor source
// ghcr.io/vendor/policies:v1.
func newInlineHarnessWith(t *testing.T, config string) (*remoteHarness, string) {
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

func TestInline_FileBundleMaterializedAndReported(t *testing.T) {
	h, _ := newInlineHarness(t)
	active := mustStartup(t, h.rc)
	dir, ok := active.runtime.inlinePolicyDirs["inline:ssh"]
	if !ok || dir != filepath.Join(h.dir, "policies", "_inline", "ssh", "policies") {
		t.Fatalf("plugins must receive the bundle's stable link: %v", active.runtime.inlinePolicyDirs)
	}
	if tree := active.runtime.inlineTrees["inline:ssh"]; !strings.HasPrefix(tree, filepath.Join(h.dir, "state", "inline", "ssh")) {
		t.Fatalf("inline bundle not materialized under the state dir: %s", tree)
	}
	for _, f := range []string{"banner.rego", "extra.rego"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("%s missing from the materialized tree: %v", f, err)
		}
	}
	r := h.remote.lastReport(t)
	if len(r.PolicyBundles) != 1 || r.PolicyBundles[0].Source != "inline:ssh" || r.PolicyBundles[0].Extends == nil || len(r.PolicyBundles[0].Extends.Files) != 1 || len(r.PolicyBundles[0].Files) != 2 {
		t.Fatalf("unexpected policy-bundles %+v", r.PolicyBundles)
	}
}

func TestInline_OverlayParseErrorKeepsRunning(t *testing.T) {
	h, _ := newInlineHarness(t)
	h.remote.publish(1, `{"policy_bundles":{"ssh":{"modules":{"extra.rego":"package compliance_framework.extra\n\nviolation contains x if {"}}}}`)
	active := mustStartup(t, h.rc)
	if active.overlay != nil {
		t.Fatal("a policy with a parse error must not be applied")
	}
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusRejected || r.Reason != agentconfig.ReasonPolicyErrors {
		t.Fatalf("expected rejected/policy-errors, got %s/%s", r.Status, r.Reason)
	}
	found := false
	for _, e := range r.PolicyErrors {
		if e.Severity == agentconfig.SeverityError && e.Path == "extra.rego" && e.Row > 0 && e.Col > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a located policy error, got %+v", r.PolicyErrors)
	}
}

func TestInline_TransitiveDeniedBuiltinRejected(t *testing.T) {
	h, vendor := newInlineHarness(t)
	if err := os.WriteFile(filepath.Join(vendor, "lib.rego"), []byte("package ccf_libs.net\n\nimport rego.v1\n\nfetch(u) := http.send({\"method\": \"GET\", \"url\": u})\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.remote.publish(1, `{"policy_bundles":{"ssh":{"modules":{"extra.rego":"package compliance_framework.extra\n\nimport rego.v1\nimport data.ccf_libs.net\n\ntitle := \"extra\"\n\nviolation contains {\"remarks\": r} if r := net.fetch(\"http://x\")\n"}}}}`)
	mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusRejected || r.Reason != agentconfig.ReasonPolicyErrors || !strings.Contains(*r.Error, "http.send") {
		t.Fatalf("expected the helper-wrapped http.send to be rejected, got %s/%s %v", r.Status, r.Reason, derefString(r.Error))
	}
}

func TestInline_DownloadPoliciesNeverDownloadsInline(t *testing.T) {
	ar := NewAgentRunner()
	ar.UpdateConfig(&agentConfig{
		Plugins: map[string]*agentPlugin{
			"ssh": {Source: "/tmp/plugin", Policies: []agentPolicy{"inline:ssh"}},
		},
		inlinePolicyDirs: map[string]string{"inline:ssh": "/materialized/ssh"},
	})
	if err := ar.DownloadPolicies(context.Background()); err != nil {
		t.Fatalf("an inline source must not be downloaded: %v", err)
	}
	if got := ar.policyLocations["inline:ssh"]; got != "/materialized/ssh" {
		t.Fatalf("policy location = %q", got)
	}
}

// TestInline_GCAfterSwap bounds the materialized directories of a long-running daemon: GC runs
// after every swap, not only at startup.
func TestInline_GCAfterSwap(t *testing.T) {
	h, _ := newInlineHarness(t)
	h.remote.publish(0, `{}`)
	mustStartup(t, h.rc)
	for rev := int64(1); rev <= 10; rev++ {
		overlay := fmt.Sprintf(`{"policy_bundles":{"ssh":{"modules":{"extra.rego":"package compliance_framework.extra\n\n# rev %d\ntitle := \"extra\"\n\nviolation contains {\"remarks\": \"x\"} if input.max > data.max\n"}}}}`, rev)
		h.remote.publish(rev, overlay)
		if got := h.poll(t); got.overlay == nil || got.overlay.Revision != rev {
			r := h.remote.lastReport(t)
			t.Fatalf("revision %d did not apply: %s/%s %s", rev, r.Status, r.Reason, derefString(r.Error))
		}
	}
	entries, err := os.ReadDir(filepath.Join(h.rc.inlineLayout().Store, "ssh"))
	if err != nil {
		t.Fatal(err)
	}
	dirs := 0
	for _, e := range entries {
		if e.IsDir() {
			dirs++
		}
	}
	if dirs > inlineGCKeepPerBundle+2 {
		t.Fatalf("expected at most %d materialized dirs after GC, found %d", inlineGCKeepPerBundle+2, dirs)
	}
	// The stable path points at the running tree.
	running := h.rc.running().runtime
	got, err := filepath.EvalSymlinks(running.inlinePolicyDirs["inline:ssh"])
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(running.inlineTrees["inline:ssh"])
	if got != want {
		t.Fatalf("the stable path resolves to %s, want the running tree %s", got, want)
	}
}

// TestInline_DuplicateIdentityAcrossPolicyPaths_R75: a plugin that loads both the vendor
// source and an inline bundle extending it from the config file gets a warning naming both
// paths (R34: file problems only warn); the revision still applies.
func TestInline_DuplicateIdentityAcrossPolicyPaths_R75(t *testing.T) {
	h, _ := newInlineHarnessWith(t, strings.Replace(inlineBaseConfig, `policies: ["inline:ssh"]`, `policies: ["ghcr.io/vendor/policies:v1", "inline:ssh"]`, 1))
	mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusApplied && r.Status != agentconfig.StatusNotApplicable {
		t.Fatalf("a duplicate from the file is a warning only, got %s/%s", r.Status, r.Reason)
	}
	var found bool
	for _, e := range r.PolicyErrors {
		if e.Code == agentconfig.PolicyCodeDuplicatePolicyIdentity {
			found = e.Severity == agentconfig.SeverityWarning && e.Bundle == "ssh" && e.Path == "banner.rego" &&
				strings.Contains(e.Message, "compliance_framework.banner") &&
				strings.Contains(e.Message, "ghcr.io/vendor/policies:v1") && strings.Contains(e.Message, "inline:ssh")
		}
		if e.Code == codeDuplicatePolicyPackage {
			t.Fatalf("the identity problem replaces the package warning for the same package: %+v", e)
		}
	}
	if !found {
		t.Fatalf("expected a duplicate-policy-identity warning naming both paths, got %+v", r.PolicyErrors)
	}

	// Replacing the source with the inline bundle (the R22 swap) clears it.
	h, _ = newInlineHarness(t)
	mustStartup(t, h.rc)
	for _, e := range h.remote.lastReport(t).PolicyErrors {
		if e.Code == agentconfig.PolicyCodeDuplicatePolicyIdentity || e.Code == codeDuplicatePolicyPackage {
			t.Fatalf("no warning expected without the duplicate path: %+v", e)
		}
	}
}

// TestInline_OverlayDuplicateIdentityRejected_R75: an overlay that lists the inline bundle
// next to the source it extends is rejected.
func TestInline_OverlayDuplicateIdentityRejected_R75(t *testing.T) {
	h, _ := newInlineHarness(t)
	h.remote.publish(1, `{"plugins":{"ssh":{"policies":["ghcr.io/vendor/policies:v1","inline:ssh"]}}}`)
	active := mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if active.overlay != nil || r.Status != agentconfig.StatusRejected || r.Reason != agentconfig.ReasonPolicyErrors {
		t.Fatalf("expected rejected/policy-errors, got %s/%s", r.Status, r.Reason)
	}
	if errs := rejectionErrors(r, agentconfig.PolicyCodeDuplicatePolicyIdentity); len(errs) != 1 || errs[0].Path != "banner.rego" {
		t.Fatalf("expected one duplicate-policy-identity error, got %+v", r.PolicyErrors)
	}
}

// TestInline_PolicyIDIdentities_R75: a policy_id that continues the vendor stream collides
// with the vendor module when both are loaded; a policy_id declared twice across a plugin's
// paths is a duplicate-policy-id.
func TestInline_PolicyIDIdentities_R75(t *testing.T) {
	t.Run("continuing id next to the vendor source", func(t *testing.T) {
		h, vendor := newInlineHarness(t)
		// A policy_id that continues the vendor stream: <vendor plugin path>/<file>.
		override := fmt.Sprintf("package compliance_framework.banner\n\nimport rego.v1\n\npolicy_id := %q\n\ntitle := \"banner\"\n\nviolation[{\"id\": \"b\"}] if not input.banner\n", vendor+"/banner.rego")
		src, _ := json.Marshal(override)
		h.remote.publish(1, `{"plugins":{"ssh":{"policies":["ghcr.io/vendor/policies:v1","inline:ssh"]}},"policy_bundles":{"ssh":{"modules":{"banner.rego":`+string(src)+`}}}}`)
		mustStartup(t, h.rc)
		r := h.remote.lastReport(t)
		errs := rejectionErrors(r, agentconfig.PolicyCodeDuplicatePolicyIdentity)
		if r.Status != agentconfig.StatusRejected || len(errs) != 1 || errs[0].Path != "banner.rego" || !strings.Contains(errs[0].Message, "same evidence stream") {
			t.Fatalf("expected a same-stream duplicate-policy-identity error, got %s %+v", r.Status, r.PolicyErrors)
		}
	})
	t.Run("same policy_id in two paths", func(t *testing.T) {
		h, vendor := newInlineHarness(t)
		if err := os.WriteFile(filepath.Join(vendor, "motd.rego"), []byte("package compliance_framework.motd\n\nimport rego.v1\n\npolicy_id := \"shared\"\n\ntitle := \"motd\"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		h.remote.publish(1, `{"policy_bundles":{"ssh":{"modules":{"extra.rego":"package compliance_framework.extra\n\nimport rego.v1\n\npolicy_id := \"shared\"\n\ntitle := \"extra\"\n"}}}}`)
		mustStartup(t, h.rc)
		r := h.remote.lastReport(t)
		errs := rejectionErrors(r, agentconfig.PolicyCodeDuplicatePolicyID)
		if r.Status != agentconfig.StatusRejected || len(errs) != 1 || errs[0].Path != "extra.rego" || !strings.Contains(errs[0].Message, `"shared"`) {
			t.Fatalf("expected a duplicate-policy-id error at the authored module, got %s %+v", r.Status, r.PolicyErrors)
		}
	})
}

// TestInline_StablePathSwapsOnlyBetweenRuns_R67: a revision prepared while a run is in
// progress does not move the stable path under it; the run loop points it at the new tree
// before the next run, and back at the previous tree when it falls back.
func TestInline_StablePathSwapsOnlyBetweenRuns_R67(t *testing.T) {
	h, _ := newInlineHarness(t)
	h.remote.publish(0, `{}`)
	active, err := h.rc.startup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stable := active.runtime.inlinePolicyDirs["inline:ssh"]
	resolve := func() string {
		t.Helper()
		got, err := filepath.EvalSymlinks(stable)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	treeOf := func(cfg *agentConfig) string {
		got, _ := filepath.EvalSymlinks(cfg.inlineTrees["inline:ssh"])
		return got
	}

	var runs []string
	var firstTree string
	errStop := errors.New("stop")
	err = h.rc.run(active, func(ctx context.Context, cfg *agentConfig) error {
		if cfg.inlinePolicyDirs["inline:ssh"] != stable {
			t.Errorf("plugins must always get the stable path, got %s", cfg.inlinePolicyDirs["inline:ssh"])
		}
		if resolve() != treeOf(cfg) {
			t.Errorf("run %d: the stable path does not point at the run's tree", len(runs)+1)
		}
		runs = append(runs, treeOf(cfg))
		switch len(runs) {
		case 1:
			firstTree = resolve()
			// A new revision arrives and is prepared while this run is in progress.
			h.remote.publish(1, `{"policy_bundles":{"ssh":{"modules":{"extra.rego":"package compliance_framework.extra\n\ntitle := \"extra v2\"\n"}}}}`)
			h.rc.reconcile(context.Background(), triggerPoll)
			if ctx.Err() == nil {
				t.Error("the swap must cancel the running configuration")
			}
			if resolve() != firstTree {
				t.Error("the stable path moved while the previous configuration was still running")
			}
			return nil
		case 2:
			if resolve() == firstTree {
				t.Error("the new run must see the new tree")
			}
			return errStop // fall back to the first configuration
		default:
			if resolve() != firstTree {
				t.Error("the fallback must point the stable path back at its tree")
			}
			return errStop
		}
	})
	if !errors.Is(err, errStop) || len(runs) != 3 {
		t.Fatalf("run returned %v after %d runs", err, len(runs))
	}
}

// TestInline_EvidenceSourceIsTheBundle (design §13.4, #96/#97): an inline bundle's evidence
// records the bundle entry and its digest, keyed by the stable path plugins receive (R67),
// and an OCI source keeps its own source.
func TestInline_EvidenceSourceIsTheBundle(t *testing.T) {
	h, _ := newInlineHarness(t)
	h.remote.publish(0, `{}`)
	mustStartup(t, h.rc)
	cfg := h.rc.running().runtime
	stable := cfg.inlinePolicyDirs["inline:ssh"]
	if !strings.HasSuffix(filepath.ToSlash(stable), "/_inline/ssh/policies") {
		t.Fatalf("plugins must receive the stable path, got %s", stable)
	}
	got := cfg.policySource("inline:ssh", stable)
	var tree string
	for _, b := range h.rc.running().bundles {
		if b.Source == "inline:ssh" {
			tree = b.Digest
		}
	}
	if got.Reference != "inline:ssh" || !got.BundleArtifact || got.Digest == "" || got.Digest != tree {
		t.Fatalf("inline source = %+v, want inline:ssh with the reported tree digest %q as fallback", got, tree)
	}
	if oci := cfg.policySource("ghcr.io/vendor/policies:v1", t.TempDir()); oci.Reference != "ghcr.io/vendor/policies:v1" || oci.BundleArtifact {
		t.Fatalf("OCI source = %+v", oci)
	}
}

// TestInline_FileDuplicateStaysAWarningUnderAnOverlay_R75: an overlay that only reorders a
// plugin's policies does not introduce the file's duplicate, so it still applies.
func TestInline_FileDuplicateStaysAWarningUnderAnOverlay_R75(t *testing.T) {
	h, _ := newInlineHarnessWith(t, strings.Replace(inlineBaseConfig, `policies: ["inline:ssh"]`, `policies: ["ghcr.io/vendor/policies:v1", "inline:ssh"]`, 1))
	withPluginLib(h, "v0.7.0") // file bundles on an old plugin only warn too
	h.remote.publish(1, `{"plugins":{"ssh":{"policies":["inline:ssh","ghcr.io/vendor/policies:v1"]}}}`)
	active := mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if active.overlay == nil || r.Status != agentconfig.StatusApplied {
		t.Fatalf("expected the reorder to apply, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
	}
	for _, code := range []string{agentconfig.PolicyCodeDuplicatePolicyIdentity, agentconfig.PolicyCodePluginLibViolationSetUnsupported} {
		got := policyErrorsWithCode(r, code)
		if len(got) == 0 {
			t.Fatalf("expected a %s warning, got %+v", code, r.PolicyErrors)
		}
		for _, e := range got {
			if e.Severity != agentconfig.SeverityWarning {
				t.Fatalf("%s must stay a warning: %+v", code, e)
			}
		}
	}
}
