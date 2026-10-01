package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/agent/internal/policyview"
	policy_manager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/hashicorp/go-hclog"
)

// Path shadowing: a plugin receives an inline bundle that extends a relative (OCI) source at
// the source's own path, and runs in a view where that path resolves to the bundle's tree.

const (
	shadowSource = "ghcr.io/vendor/policies:v1"
	// Where the agent extracts the OCI source: relative to its working directory.
	shadowExtracted = ".compliance-framework/policies/vendor/policies/v1/policies"
	// A plugin built on agent v0.1.9 (plugin-local-ssh v0.2.0): no policy_id, no set-form
	// violations.
	oldLib = "v0.1.9-0.20250708121809-c5059c3efac8"
)

var shadowVendor = map[string]string{
	"banner.rego":      "package compliance_framework.banner\n\nimport rego.v1\n\ntitle := \"Banner\"\n\nviolation[{\"id\": \"b\"}] if not input.banner\n",
	"keys.rego":        "package compliance_framework.keys\n\nimport rego.v1\n\ntitle := \"Keys\"\n\nviolation[{\"id\": \"k\"}] if input.password\n",
	"keys_test.rego":   "package compliance_framework.keys_test\n\nimport rego.v1\n\ntest_ok if true\n",
	"lib/helpers.rego": "package ccf_libs.helpers\n\nimport rego.v1\n\nyes := true\n",
}

const shadowConfig = `
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
policy_bundles:
  ssh:
    extends: ghcr.io/vendor/policies:v1
    modules:
      keys.rego: |
        package compliance_framework.keys

        import rego.v1

        title := "Keys (tuned)"

        violation[{"id": "k2"}] if input.password
      added.rego: |
        package compliance_framework.added

        import rego.v1

        title := "Added"

        violation[{"id": "a"}] if input.password
`

// shadowHarness changes to a new working directory holding the extracted vendor source and
// returns a harness on config whose policy sources resolve like the agent's (relative paths).
func shadowHarness(t *testing.T, config string) *remoteHarness {
	t.Helper()
	t.Chdir(t.TempDir())
	skipWithoutSymlinksHere(t)
	for p, src := range shadowVendor {
		dst := filepath.Join(shadowExtracted, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h := newRemoteHarness(t, config)
	h.rc.inlineLinks = "" // the agent's default, relative to the working directory
	h.rc.resolvePolicy = func(_ context.Context, source string) (string, error) {
		if source == shadowSource {
			return shadowExtracted, nil
		}
		return "", errors.New("unknown source " + source)
	}
	return h
}

func skipWithoutSymlinksHere(t *testing.T) {
	t.Helper()
	if err := os.Symlink(".", "probe"); err != nil {
		t.Skip("symlinks are not supported here")
	}
	_ = os.Remove("probe")
}

type shadowEvidence struct {
	uuid, title string
	labels      map[string]string
}

// evaluateIn evaluates policyPath with the working directory dir, the way the ssh plugin
// does (labels with the literal _policy_path), and returns the evidence by package.
func evaluateIn(t *testing.T, dir, policyPath string) map[string]shadowEvidence {
	t.Helper()
	back, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(back) }()
	labels := map[string]string{"type": "ssh", "hostname": "kube-prod-worker-1", "_policy_path": policyPath}
	evidence, err := policy_manager.NewPolicyProcessor(hclog.NewNullLogger(), labels, nil, nil, nil, nil, nil, nil).
		GenerateResults(context.Background(), policyPath, map[string]any{"password": true})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]shadowEvidence{}
	for _, e := range evidence {
		out[e.Labels["_policy"]] = shadowEvidence{uuid: e.UUID, title: e.Title, labels: e.Labels}
	}
	return out
}

func TestShadow_PluginReceivesTheVendorPathInItsView(t *testing.T) {
	h := shadowHarness(t, shadowConfig)
	withPluginLib(h, oldLib)
	active := mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusApplied && r.Status != agentconfig.StatusNotApplicable {
		t.Fatalf("expected the file bundle to load, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
	}

	// The plugin receives the vendor's exact path string.
	if got := active.runtime.inlinePolicyDirs["inline:ssh"]; got != shadowExtracted {
		t.Fatalf("plugins receive %q, want the extends source's path %q", got, shadowExtracted)
	}
	view := active.runtime.pluginViews["ssh"]
	if view == nil {
		t.Fatal("the plugin has no view")
	}
	workDir, err := active.runtime.pluginWorkDir("ssh")
	if err != nil || workDir != view.Dir {
		t.Fatalf("plugin work dir = %q, %v; want the view %q", workDir, err, view.Dir)
	}

	// Inside the view the path is the bundle's tree; outside it, still the vendor's.
	tree := active.runtime.inlineTrees["inline:ssh"]
	inView, err := filepath.EvalSymlinks(view.Resolve(shadowExtracted))
	if err != nil {
		t.Fatal(err)
	}
	wantTree, _ := filepath.EvalSymlinks(tree)
	if inView != wantTree {
		t.Fatalf("in the view %s resolves to %s, want the bundle's tree %s", shadowExtracted, inView, wantTree)
	}
	if raw, err := os.ReadFile(filepath.Join(shadowExtracted, "keys.rego")); err != nil || string(raw) != shadowVendor["keys.rego"] {
		t.Fatalf("the agent's own view of the vendor tree must be untouched: %q %v", raw, err)
	}
	// The path string carries the identity: inherited modules are the vendor's bytes.
	raw, err := os.ReadFile(filepath.Join(tree, "banner.rego"))
	if err != nil || string(raw) != shadowVendor["banner.rego"] {
		t.Fatalf("an inherited module must be the vendor's bytes, got %q %v", raw, err)
	}

	// Report: an old library is fine, and there are no stream warnings.
	for _, code := range []string{inlinepolicy.CodePolicyStreamForked, agentconfig.PolicyCodeDuplicatePolicyIdentity} {
		if got := policyErrorsWithCode(r, code); len(got) != 0 {
			t.Fatalf("unexpected %s: %+v", code, got)
		}
	}
	if len(r.Plugins) != 1 || r.Plugins[0].LibVersion != oldLib {
		t.Fatalf("plugins report = %+v", r.Plugins)
	}

	// Evidence: inherited and overridden modules keep the vendor UUIDs, added ones get new
	// streams, and the modules really load from the bundle (the tuned title).
	base, _ := os.Getwd()
	vendor := evaluateIn(t, base, shadowExtracted)
	got := evaluateIn(t, view.Dir, shadowExtracted)
	if len(got) != 3 {
		t.Fatalf("expected banner, keys and added evidence in the view, got %+v", got)
	}
	for _, pkg := range []string{"compliance_framework.banner", "compliance_framework.keys"} {
		if got[pkg].uuid == "" || got[pkg].uuid != vendor[pkg].uuid {
			t.Fatalf("%s: UUID %s, want the vendor's %s", pkg, got[pkg].uuid, vendor[pkg].uuid)
		}
		if got[pkg].labels["_policy_path"] != shadowExtracted {
			t.Fatalf("%s: _policy_path = %q", pkg, got[pkg].labels["_policy_path"])
		}
		if _, ok := got[pkg].labels["_policy_id"]; ok {
			t.Fatalf("%s: no _policy_id expected with shadowing", pkg)
		}
	}
	if got["compliance_framework.keys"].title != "Keys (tuned)" {
		t.Fatalf("the override must be evaluated, got title %q", got["compliance_framework.keys"].title)
	}
	added := got["compliance_framework.added"].uuid
	if added == "" {
		t.Fatal("the added module produced no evidence")
	}
	for _, e := range vendor {
		if e.uuid == added {
			t.Fatal("an added module must have its own stream")
		}
	}
}

// TestShadow_NewRevisionIsANewView: editing the bundle gives the plugin a new view (no swap
// under a running plugin), the same path, and the same streams; GC removes the old view
// once no candidate uses it.
func TestShadow_NewRevisionIsANewView(t *testing.T) {
	h := shadowHarness(t, shadowConfig)
	withPluginLib(h, oldLib)
	first := mustStartup(t, h.rc)
	firstView := first.runtime.pluginViews["ssh"].Dir
	base, _ := os.Getwd()
	before := evaluateIn(t, firstView, shadowExtracted)

	h.remote.publish(1, `{"policy_bundles":{"ssh":{"modules":{"added.rego":"package compliance_framework.added\n\nimport rego.v1\n\ntitle := \"Added v2\"\n\nviolation[{\"id\": \"a\"}] if input.password\n"}}}}`)
	resolve := h.rc.resolvePolicy
	h.rc = h.newReconciler() // a restart picks the revision up
	h.rc.inlineLinks = ""
	h.rc.resolvePolicy = resolve
	withPluginLib(h, oldLib)
	second := mustStartup(t, h.rc)
	if second.overlay == nil {
		r := h.remote.lastReport(t)
		t.Fatalf("the edit must apply: %s/%s %v %+v", r.Status, r.Reason, derefString(r.Error), r.PolicyErrors)
	}
	secondView := second.runtime.pluginViews["ssh"].Dir
	if secondView == firstView {
		t.Fatal("a new tree must be a new view")
	}
	if second.runtime.inlinePolicyDirs["inline:ssh"] != shadowExtracted {
		t.Fatal("the plugin path must not change")
	}
	after := evaluateIn(t, secondView, shadowExtracted)
	for pkg, e := range before {
		if after[pkg].uuid != e.uuid {
			t.Fatalf("%s changed stream across revisions", pkg)
		}
	}
	if after["compliance_framework.added"].title != "Added v2" {
		t.Fatalf("the new view must hold the new tree, got %q", after["compliance_framework.added"].title)
	}

	h.rc.mu.Lock()
	h.rc.active, h.rc.pending, h.rc.starting, h.rc.fallback = second, nil, nil, nil
	h.rc.mu.Unlock()
	h.rc.gcInline()
	if _, err := os.Lstat(firstView); !os.IsNotExist(err) {
		t.Fatalf("the old view must be collected: %v", err)
	}
	if _, err := os.Stat(filepath.Join(secondView, shadowExtracted, "keys.rego")); err != nil {
		t.Fatalf("the active view must stay: %v", err)
	}
	// Removing a view never follows its links.
	if _, err := os.Stat(filepath.Join(base, shadowExtracted, "keys.rego")); err != nil {
		t.Fatalf("GC must not touch the vendor tree: %v", err)
	}
}

// TestShadow_PluginAlsoLoadingTheSourceFallsBack: a plugin that loads the source and the
// bundle together cannot be given a view; plugins receive the bundle at its own path under
// _inline, its inherited modules start new streams (policy-stream-forked), and the duplicate
// is reported (R75): a warning from the file, an error when the overlay introduces it.
func TestShadow_PluginAlsoLoadingTheSourceFallsBack(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		h := shadowHarness(t, strings.Replace(shadowConfig, `policies: ["inline:ssh"]`, `policies: ["inline:ssh", "ghcr.io/vendor/policies:v1"]`, 1))
		withPluginLib(h, "v0.9.0")
		active := mustStartup(t, h.rc)
		if got := active.runtime.inlinePolicyDirs["inline:ssh"]; filepath.ToSlash(got) != ".compliance-framework/policies/_inline/ssh/policies" {
			t.Fatalf("plugins receive %q, want the bundle's own path", got)
		}
		if active.runtime.pluginViews["ssh"] != nil {
			t.Fatal("no view without a shadowed bundle")
		}
		raw, _ := os.ReadFile(filepath.Join(active.runtime.inlineTrees["inline:ssh"], "banner.rego"))
		if string(raw) != shadowVendor["banner.rego"] {
			t.Fatalf("an inherited module keeps the vendor bytes, got %q", raw)
		}
		forked := policyErrorsWithCode(h.remote.lastReport(t), inlinepolicy.CodePolicyStreamForked)
		if len(forked) == 0 || forked[0].Path != "" || !strings.Contains(forked[0].Message, "inherited modules (banner.rego)") {
			t.Fatalf("expected a policy-stream-forked warning for the inherited module, got %+v", h.remote.lastReport(t).PolicyErrors)
		}
		dups := policyErrorsWithCode(h.remote.lastReport(t), agentconfig.PolicyCodeDuplicatePolicyIdentity)
		if len(dups) == 0 || dups[0].Severity != agentconfig.SeverityWarning {
			t.Fatalf("expected a duplicate-policy-identity warning, got %+v", h.remote.lastReport(t).PolicyErrors)
		}
	})
	t.Run("overlay", func(t *testing.T) {
		h := shadowHarness(t, shadowConfig)
		withPluginLib(h, "v0.9.0")
		h.remote.publish(1, `{"plugins":{"ssh":{"policies":["inline:ssh","ghcr.io/vendor/policies:v1"]}}}`)
		active := mustStartup(t, h.rc)
		r := h.remote.lastReport(t)
		if active.overlay != nil || r.Status != agentconfig.StatusRejected {
			t.Fatalf("loading the source next to its bundle must be rejected, got %s/%s", r.Status, r.Reason)
		}
		if len(rejectionErrors(r, agentconfig.PolicyCodeDuplicatePolicyIdentity)) == 0 {
			t.Fatalf("expected duplicate-policy-identity errors, got %+v", r.PolicyErrors)
		}
		if active.runtime.inlinePolicyDirs["inline:ssh"] != shadowExtracted {
			t.Fatal("the running file configuration keeps its shadowed bundle")
		}
	})
}

// TestShadow_AbsoluteExtendsIsNotShadowed: a bundle extending an absolute path cannot be
// shadowed; an overlay editing it applies on an old plugin, its modules start new streams
// (warned about) and the plugin gets no view.
func TestShadow_AbsoluteExtendsIsNotShadowed(t *testing.T) {
	h, _ := newInlineHarness(t) // the vendor is an absolute temp dir
	withPluginLib(h, oldLib)
	h.remote.publish(1, `{"policy_bundles":{"ssh":{"modules":{"extra.rego":"package compliance_framework.extra\n\nimport rego.v1\n\ntitle := \"extra v2\"\n\nviolation[{\"id\": \"x\"}] if input.max > data.max\n"}}}}`)
	active := mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if active.overlay == nil || r.Status != agentconfig.StatusApplied {
		t.Fatalf("expected applied, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
	}
	if forked := policyErrorsWithCode(r, inlinepolicy.CodePolicyStreamForked); len(forked) != 1 || forked[0].Severity != agentconfig.SeverityWarning {
		t.Fatalf("expected one policy-stream-forked warning for the inherited module, got %+v", r.PolicyErrors)
	}
	if active.runtime.pluginViews["ssh"] != nil {
		t.Fatal("an absolute extends path gets no view")
	}
}

// TestShadow_OldLibOverlay: an overlay that edits a shadowed bundle of a plugin built on
// agent v0.1.9 applies; a set-form violation in it is still rejected (old policy-managers
// panic on it).
func TestShadow_OldLibOverlay(t *testing.T) {
	t.Run("object form applies", func(t *testing.T) {
		h := shadowHarness(t, shadowConfig)
		withPluginLib(h, oldLib)
		h.remote.publish(1, `{"policy_bundles":{"ssh":{"modules":{"new.rego":"package compliance_framework.new\n\nimport rego.v1\n\npolicy_id := \"ssh/new\"\n\ntitle := \"New\"\n\nviolation[{\"id\": \"n\"}] if input.password\n"}}}}`)
		active := mustStartup(t, h.rc)
		r := h.remote.lastReport(t)
		if active.overlay == nil || r.Status != agentconfig.StatusApplied {
			t.Fatalf("expected applied, got %s/%s %+v", r.Status, r.Reason, r.PolicyErrors)
		}
		ids := policyErrorsWithCode(r, agentconfig.PolicyCodePluginLibPolicyIDUnsupported)
		if len(ids) != 1 || ids[0].Severity != agentconfig.SeverityWarning || ids[0].Path != "new.rego" {
			t.Fatalf("an ignored policy_id is a warning, got %+v", r.PolicyErrors)
		}
	})
	t.Run("set form is rejected", func(t *testing.T) {
		h := shadowHarness(t, shadowConfig)
		withPluginLib(h, oldLib)
		h.remote.publish(1, `{"policy_bundles":{"ssh":{"modules":{"new.rego":"package compliance_framework.new\n\nimport rego.v1\n\ntitle := \"New\"\n\nviolation contains {\"id\": \"n\"} if input.password\n"}}}}`)
		active := mustStartup(t, h.rc)
		r := h.remote.lastReport(t)
		if active.overlay != nil || r.Status != agentconfig.StatusRejected {
			t.Fatalf("expected rejected, got %s/%s", r.Status, r.Reason)
		}
		set := rejectionErrors(r, agentconfig.PolicyCodePluginLibViolationSetUnsupported)
		if len(set) != 1 || set[0].Path != "new.rego" {
			t.Fatalf("expected the set-form error, got %+v", r.PolicyErrors)
		}
	})
}

// TestShadow_PluginOwnedViewEntries (rule 1): a plugin that creates a directory relative to
// its working directory creates it in its view. When the agent's working directory later
// gets the same name, the plugin keeps its own; neither activation nor the plugin's run
// fails, and the warning is logged once. A real entry at the shadow link itself is a
// conflict: the plugin's run fails with a clear error, activation only logs it, and the
// entry is left alone.
func TestShadow_PluginOwnedViewEntries(t *testing.T) {
	h := shadowHarness(t, shadowConfig)
	withPluginLib(h, oldLib)
	var logs strings.Builder
	h.rc.logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn})
	active := mustStartup(t, h.rc)
	if err := h.rc.activateInline(active); err != nil {
		t.Fatal(err)
	}
	view := active.runtime.pluginViews["ssh"]
	if view == nil {
		t.Fatal("the plugin has no view")
	}

	// cloud-custodian writes debug-standardized-payloads/ relative to its working directory.
	owned := filepath.Join(view.Dir, "debug-standardized-payloads")
	if err := os.MkdirAll(owned, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(owned, "payload.json"), []byte("plugin"), 0o644); err != nil {
		t.Fatal(err)
	}
	// ... and later, so does something in the agent's working directory.
	if err := os.MkdirAll("debug-standardized-payloads", 0o755); err != nil {
		t.Fatal(err)
	}

	for range 3 {
		if err := h.rc.activateInline(active); err != nil {
			t.Fatalf("activation must not fail on a plugin-owned entry: %v", err)
		}
		if dir, err := active.runtime.pluginWorkDir("ssh"); err != nil || dir != view.Dir {
			t.Fatalf("the plugin's run must not fail on a plugin-owned entry: %q %v", dir, err)
		}
	}
	if n := strings.Count(logs.String(), "path=debug-standardized-payloads"); n != 1 || strings.Count(logs.String(), "[WARN]") != 1 {
		t.Fatalf("want one warning naming the entry, got %d:\n%s", n, logs.String())
	}
	if raw, err := os.ReadFile(filepath.Join(owned, "payload.json")); err != nil || string(raw) != "plugin" {
		t.Fatalf("the plugin's entry must be kept: %q %v", raw, err)
	}

	// The shadow link is the agent's: a real entry there is a conflict, never removed.
	link := filepath.Join(view.Dir, filepath.Dir(shadowExtracted))
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(link, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	var conflict *policyview.LinkConflictError
	if err := h.rc.activateInline(active); err != nil {
		t.Fatalf("a view's conflict must not fail activation, got %v", err)
	}
	if _, err := active.runtime.pluginWorkDir("ssh"); !errors.As(err, &conflict) {
		t.Fatalf("the run must fail with a link conflict, got %v", err)
	}
	if info, err := os.Lstat(link); err != nil || !info.IsDir() {
		t.Fatalf("the conflicting entry must be left alone: %v", err)
	}
}

// TestShadow_ViewConflictFailsOnlyThatPlugin (M1): a conflict in one plugin's view fails
// only that plugin's runs. Activation logs it and carries on, another plugin's view is
// still prepared, and a restart (the view is content-addressed, so the conflict persists)
// still starts the configuration instead of exiting.
func TestShadow_ViewConflictFailsOnlyThatPlugin(t *testing.T) {
	config := strings.Replace(shadowConfig, `    policies: ["inline:ssh"]`, `    policies: ["inline:ssh"]
  other:
    source: ghcr.io/compliance-framework/plugin-other:v1
    policies: ["inline:ssh"]`, 1)
	h := shadowHarness(t, config)
	withPluginLib(h, oldLib)
	active := mustStartup(t, h.rc)
	ssh, other := active.runtime.pluginViews["ssh"], active.runtime.pluginViews["other"]
	if ssh == nil || other == nil || ssh.Dir == other.Dir {
		t.Fatalf("each plugin needs its own view: %+v", active.runtime.pluginViews)
	}

	// The ssh plugin replaced its shadow link with a directory of its own.
	link := filepath.Join(ssh.Dir, filepath.Dir(shadowExtracted))
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(link, "policies"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(other.Dir); err != nil { // and the other view must be rebuilt
		t.Fatal(err)
	}

	var logs strings.Builder
	h.rc.logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn})
	if err := h.rc.activateInline(active); err != nil {
		t.Fatalf("one plugin's view must not fail the configuration: %v", err)
	}
	if !strings.Contains(logs.String(), "plugin=ssh") {
		t.Fatalf("the conflict must be logged with the plugin, got:\n%s", logs.String())
	}
	if _, err := os.Stat(filepath.Join(other.Dir, shadowExtracted, "keys.rego")); err != nil {
		t.Fatalf("the other plugin's view must be prepared: %v", err)
	}
	if dir, err := active.runtime.pluginWorkDir("other"); err != nil || dir != other.Dir {
		t.Fatalf("the other plugin must run: %q %v", dir, err)
	}
	var conflict *policyview.LinkConflictError
	if _, err := active.runtime.pluginWorkDir("ssh"); !errors.As(err, &conflict) {
		t.Fatalf("the conflicting plugin's run must fail with the link conflict, got %v", err)
	}

	// A restart finds the same view: the configuration still starts.
	resolve := h.rc.resolvePolicy
	h.rc = h.newReconciler()
	h.rc.inlineLinks = ""
	h.rc.resolvePolicy = resolve
	withPluginLib(h, oldLib)
	restarted := mustStartup(t, h.rc)
	if restarted.runtime.pluginViews["ssh"].Dir != ssh.Dir {
		t.Fatal("the view is content-addressed: a restart must reuse it")
	}
	if _, err := restarted.runtime.pluginWorkDir("ssh"); !errors.As(err, &conflict) {
		t.Fatalf("the conflict persists for that plugin only, got %v", err)
	}
}

// TestShadow_PlanDrops: a bundle is not shadowed for a plugin that uses a second bundle on
// the same path, or whose other policy paths cannot be resolved in a view; plugins then
// receive it at its own path, and the reason is logged.
func TestShadow_PlanDrops(t *testing.T) {
	const otherSource = "ghcr.io/vendor/other:v1"
	for _, tc := range []struct {
		name, from, to string
		// otherPath is where otherSource is extracted ("" when unused).
		otherPath, reason string
	}{
		{
			name: "two bundles on one path",
			from: "policy_bundles:\n", to: "policy_bundles:\n  ssh2:\n    extends: ghcr.io/vendor/policies:v1\n",
			reason: "uses more than one bundle that extends " + shadowExtracted,
		},
		{
			name: "a policy root in a view directory",
			from: `policies: ["inline:ssh"]`, to: `policies: ["inline:ssh", "` + otherSource + `"]`,
			otherPath: ".compliance-framework/policies/vendor/policies/other",
			reason:    "cannot be given a view",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := strings.Replace(shadowConfig, tc.from, tc.to, 1)
			if tc.otherPath == "" {
				config = strings.Replace(config, `policies: ["inline:ssh"]`, `policies: ["inline:ssh", "inline:ssh2"]`, 1)
			}
			h := shadowHarness(t, config)
			if tc.otherPath != "" {
				if err := os.MkdirAll(tc.otherPath, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(tc.otherPath, "other.rego"), []byte("package compliance_framework.other\n\nimport rego.v1\n\ntitle := \"Other\"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				vendor := h.rc.resolvePolicy
				h.rc.resolvePolicy = func(ctx context.Context, source string) (string, error) {
					if source == otherSource {
						return tc.otherPath, nil
					}
					return vendor(ctx, source)
				}
			}
			withPluginLib(h, oldLib)
			var logs strings.Builder
			h.rc.logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Info})
			active := mustStartup(t, h.rc)
			if got := active.runtime.inlinePolicyDirs["inline:ssh"]; filepath.ToSlash(got) != ".compliance-framework/policies/_inline/ssh/policies" {
				t.Fatalf("plugins receive %q, want the bundle's own path", got)
			}
			if active.runtime.pluginViews["ssh"] != nil {
				t.Fatal("no view without a shadowed bundle")
			}
			if !strings.Contains(logs.String(), "Inline bundle is not shadowed") || !strings.Contains(logs.String(), tc.reason) {
				t.Fatalf("the reason must be logged (%q), got:\n%s", tc.reason, logs.String())
			}
		})
	}
}

// TestPluginCommand: plugins start by their absolute binary path in their working directory
// (a view), without the agent's API credentials.
func TestPluginCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as the plugin")
	}
	wd := t.TempDir()
	t.Chdir(wd)
	if err := os.MkdirAll("bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("bin", "plugin"), []byte("#!/bin/sh\npwd -P\necho \"secret=$CCF_API_AUTH_CLIENT_SECRET\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CCF_API_AUTH_CLIENT_SECRET", "s3cret")
	view := t.TempDir()

	cmd := pluginCommand(filepath.Join("bin", "plugin"), view)
	if !filepath.IsAbs(cmd.Path) || cmd.Dir != view {
		t.Fatalf("path = %q, dir = %q; want an absolute binary path and the view", cmd.Path, cmd.Dir)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("a relative binary path must still start in the view: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	want, _ := filepath.EvalSymlinks(view)
	if len(lines) != 2 || lines[0] != want || lines[1] != "secret=" {
		t.Fatalf("the plugin must run in the view without the agent's credentials, got %q (view %s)", out, want)
	}

	if cmd := pluginCommand(filepath.Join("bin", "plugin"), ""); cmd.Dir != "" {
		t.Fatalf("without a view the plugin runs in the agent's working directory, got %q", cmd.Dir)
	}
}
