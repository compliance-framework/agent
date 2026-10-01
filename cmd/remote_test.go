package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/compliance-framework/agent/internal/agentstate"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/sdk"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
)

// fakeRemote is a scripted API for the remote configuration routes.
type fakeRemote struct {
	mu        sync.Mutex
	overlay   json.RawMessage // current overlay; nil = no document (404 if unsupported)
	revision  int64
	etag      string
	getErr    error
	reportErr func(n int, r agentconfig.Report) error
	gets      []string
	reports   []agentconfig.Report
	uploads   []string
	uploadErr func(n int) error
}

func (f *fakeRemote) Get(_ context.Context, ifNoneMatch string) (*sdk.AgentConfigResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, ifNoneMatch)
	if f.getErr != nil {
		return nil, f.getErr
	}
	if f.overlay == nil {
		return nil, sdk.ErrRemoteConfigUnsupported
	}
	if ifNoneMatch != "" && ifNoneMatch == f.etag {
		return &sdk.AgentConfigResult{NotModified: true, ETag: f.etag}, nil
	}
	return &sdk.AgentConfigResult{
		Document: &agentconfig.OverlayDocument{Revision: f.revision, Overlay: f.overlay},
		ETag:     f.etag,
	}, nil
}

func (f *fakeRemote) Report(_ context.Context, _ uuid.UUID, r agentconfig.Report) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, r)
	if f.reportErr != nil {
		return f.reportErr(len(f.reports), r)
	}
	return nil
}

// UploadArtifact records an artifact upload; uploadErr scripts failures.
func (f *fakeRemote) UploadArtifact(_ context.Context, mediaType string, content []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.uploads = append(f.uploads, mediaType)
	if f.uploadErr != nil {
		if err := f.uploadErr(len(f.uploads)); err != nil {
			return "", err
		}
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (f *fakeRemote) uploadCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.uploads)
}

// publish sets a new overlay revision with an opaque ETag.
func (f *fakeRemote) publish(rev int64, overlay string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revision = rev
	f.overlay = json.RawMessage(overlay)
	f.etag = fmt.Sprintf(`"r%d-%s"`, rev, uuid.New())
}

func (f *fakeRemote) lastReport(t *testing.T) agentconfig.Report {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.reports) == 0 {
		t.Fatal("no report was sent")
	}
	return f.reports[len(f.reports)-1]
}

func (f *fakeRemote) reportCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reports)
}

func (f *fakeRemote) getCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.gets)
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

const remoteBaseConfig = `
daemon: true
api:
  url: http://api.test
  auth:
    client_id: 123e4567-e89b-12d3-a456-426614174000
    client_secret: s3cret
remote_config:
  mode: %MODE%
  trusted_sources: ["ghcr.io/trusted/*"]
  overridable_config_flags: [%FLAGS%]
plugins:
  ssh:
    source: ghcr.io/compliance-framework/plugin-ssh:v1
    schedule: "* * * * *"
    config:
      host: localhost
      token: t0ken
`

type remoteHarness struct {
	rc     *reconciler
	remote *fakeRemote
	pf     *fakePrefetcher
	clock  *fakeClock
	path   string
	dir    string
}

func remoteConfig(mode, flags string) string {
	return strings.NewReplacer("%MODE%", mode, "%FLAGS%", flags).Replace(remoteBaseConfig)
}

func newRemoteHarness(t *testing.T, content string) *remoteHarness {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &remoteHarness{
		remote: &fakeRemote{},
		pf:     &fakePrefetcher{},
		clock:  &fakeClock{now: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)},
		path:   path,
		dir:    dir,
	}
	h.rc = h.newReconciler()
	return h
}

// newReconciler builds a reconciler on the harness's files (a "restart").
func (h *remoteHarness) newReconciler() *reconciler {
	rc := newReconciler(AgentCmd(), h.path, agentstate.Open(filepath.Join(h.dir, "state"), nil), h.pf, nil)
	rc.inlineLinks = filepath.Join(h.dir, "policies", "inline")
	rc.newRemote = func(agentconfig.Config) remoteAPI { return h.remote }
	rc.now = h.clock.Now
	rc.lookupEnv = func(string) (string, bool) { return "", false }
	return rc
}

func (h *remoteHarness) writeConfig(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(h.path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustStartup(t *testing.T, rc *reconciler) *candidate {
	t.Helper()
	active, err := rc.startup(context.Background())
	if err != nil {
		t.Fatalf("startup: %v", err)
	}
	if err := rc.start(active, nil, func() {}); err != nil {
		t.Fatalf("start: %v", err)
	}
	return active
}

// poll runs one poll trigger and returns the candidate now running (the pending swap, if any).
func (h *remoteHarness) poll(t *testing.T) *candidate {
	t.Helper()
	h.rc.reconcile(context.Background(), triggerPoll)
	if next := h.rc.takePending(); next != nil {
		if err := h.rc.start(next, nil, func() {}); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	return h.rc.current()
}

func TestStartupReport_RedactsAndDescribes(t *testing.T) {
	t.Setenv("CCF_PLUGINS_GITHUB_CONFIG_TOKEN", "env-secret")
	h := newRemoteHarness(t, remoteConfig("apply_safe", "")+`
  github:
    source: ghcr.io/compliance-framework/plugin-github:v1
    enabled: false
    config:
      token: from-file
      org: "${env:GITHUB_ORG}"
`)
	h.rc.lookupEnv = func(n string) (string, bool) { return "acme", n == "GITHUB_ORG" }
	h.remote.publish(0, `{}`)
	mustStartup(t, h.rc)

	r := h.remote.lastReport(t)
	for _, doc := range []json.RawMessage{r.Base, r.Effective} {
		s := string(doc)
		if strings.Contains(s, "s3cret") || strings.Contains(s, "client_secret") {
			t.Fatalf("client secret leaked: %s", s)
		}
		if strings.Contains(s, "t0ken") || strings.Contains(s, "env-secret") {
			t.Fatalf("token leaked: %s", s)
		}
		if !strings.Contains(s, `"org":"${env:GITHUB_ORG}"`) {
			t.Fatalf("placeholder must be reported as written: %s", s)
		}
		if strings.Contains(s, "acme") {
			t.Fatalf("resolved env value leaked: %s", s)
		}
		if !strings.Contains(s, `"github":{`) || !strings.Contains(s, `"enabled":false`) {
			t.Fatalf("disabled plugin must be reported: %s", s)
		}
	}
	var eff agentconfig.Config
	if err := json.Unmarshal(r.Effective, &eff); err != nil {
		t.Fatal(err)
	}
	if got := eff.Plugins["github"].Config["token"]; got != agentconfig.MaskedValue {
		t.Fatalf("env-sourced token must be %q, got %q", agentconfig.MaskedValue, got)
	}
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"remote-config":{"mode":"apply_safe","poll_interval":"60s","trusted_sources":["ghcr.io/trusted/*"]`) {
		t.Fatalf("remote-config must be snake_case inside: %s", raw)
	}
	if !r.Daemon || r.Status != agentconfig.StatusApplied || r.Mode != agentconfig.ModeApplySafe {
		t.Fatalf("unexpected report header %+v", r)
	}
	// R55: the digest is recomputable from the reported effective config, and it does not
	// change when the env-sourced value rotates.
	if got := agentconfig.Digest(eff, agentconfig.WithMaskedPointers("/plugins/github/config/token")); got != r.EffectiveDigest {
		t.Fatalf("effective-digest %s != Digest(reported effective) %s", r.EffectiveDigest, got)
	}
	t.Setenv("CCF_PLUGINS_GITHUB_CONFIG_TOKEN", "rotated")
	rotated := h.newReconciler()
	rotated.lookupEnv = h.rc.lookupEnv
	if active := mustStartup(t, rotated); active.digest != r.EffectiveDigest {
		t.Fatalf("digest changed when the env value rotated: %s vs %s", active.digest, r.EffectiveDigest)
	}
}

func TestReport_ResendPolicy(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", "")) // no document: 404 → file only
	h.remote.overlay = json.RawMessage(`{}`)
	h.remote.etag = `"r0-x"`
	mustStartup(t, h.rc)
	if h.remote.reportCount() != 1 {
		t.Fatalf("expected the startup report, got %d", h.remote.reportCount())
	}
	h.poll(t)
	if h.remote.reportCount() != 1 {
		t.Fatalf("an unchanged report must not be resent, got %d", h.remote.reportCount())
	}
	h.clock.Advance(24*time.Hour + time.Second)
	h.poll(t)
	if h.remote.reportCount() != 2 {
		t.Fatalf("expected a resend after 24h, got %d", h.remote.reportCount())
	}
	h.remote.reportErr = func(int, agentconfig.Report) error { return errors.New("network down") }
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	h.poll(t)
	if h.remote.reportCount() != 3 {
		t.Fatalf("expected a report after a change, got %d", h.remote.reportCount())
	}
	h.remote.reportErr = nil
	h.poll(t)
	if h.remote.reportCount() != 4 {
		t.Fatalf("expected a resend after a send error, got %d", h.remote.reportCount())
	}
	if r := h.remote.lastReport(t); r.AppliedRevision == nil || *r.AppliedRevision != 1 {
		t.Fatalf("expected applied revision 1, got %+v", r.AppliedRevision)
	}
}

func TestModes_ReportAndOff(t *testing.T) {
	t.Run("report mode never fetches", func(t *testing.T) {
		h := newRemoteHarness(t, remoteConfig("report", ""))
		h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
		active := mustStartup(t, h.rc)
		h.poll(t)
		if h.remote.getCount() != 0 {
			t.Fatalf("report mode must never fetch, got %d gets", h.remote.getCount())
		}
		r := h.remote.lastReport(t)
		if r.Status != agentconfig.StatusNotApplicable || r.AppliedRevision != nil {
			t.Fatalf("report mode: %+v", r)
		}
		hb := buildHeartbeat(active.runtime, uuid.New(), time.Now())
		if hb.ConfigRevision == nil || *hb.ConfigRevision != 0 || hb.ConfigDigest == "" {
			t.Fatalf("report mode heartbeat must carry revision 0 and a digest: %+v", hb)
		}
	})
	t.Run("off sends nothing", func(t *testing.T) {
		h := newRemoteHarness(t, remoteConfig("off", ""))
		active := mustStartup(t, h.rc)
		h.poll(t)
		if h.remote.reportCount() != 0 || h.remote.getCount() != 0 {
			t.Fatalf("off must not report or fetch: %d reports, %d gets", h.remote.reportCount(), h.remote.getCount())
		}
		hb := buildHeartbeat(active.runtime, uuid.New(), time.Now())
		if hb.ConfigRevision != nil || hb.ConfigDigest != "" {
			t.Fatalf("off heartbeat must not carry config fields: %+v", hb)
		}
	})
	t.Run("no auth forces off", func(t *testing.T) {
		h := newRemoteHarness(t, `
api:
  url: http://api.test
remote_config:
  mode: apply_all
`)
		active := mustStartup(t, h.rc)
		if active.runtime.remote.Mode != agentconfig.ModeOff || h.remote.reportCount() != 0 {
			t.Fatalf("expected off without auth, got %q (%d reports)", active.runtime.remote.Mode, h.remote.reportCount())
		}
	})
}

func TestHeartbeat_FileOnlyApplySafe(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	active := mustStartup(t, h.rc) // the fake answers 404: file only
	hb := buildHeartbeat(active.runtime, uuid.New(), time.Now())
	if hb.ConfigRevision == nil || *hb.ConfigRevision != 0 || hb.ConfigDigest != active.digest {
		t.Fatalf("heartbeat: %+v (digest %s)", hb, active.digest)
	}
}

func TestRemoteErrors_Backoffs(t *testing.T) {
	t.Run("404 backs off 10 minutes", func(t *testing.T) {
		h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
		mustStartup(t, h.rc)
		h.poll(t)
		if h.remote.getCount() != 1 {
			t.Fatalf("expected no fetch during the 404 backoff, got %d", h.remote.getCount())
		}
		h.clock.Advance(remoteAuthBackoff + time.Second)
		h.poll(t)
		if h.remote.getCount() != 2 {
			t.Fatalf("expected a fetch after the backoff, got %d", h.remote.getCount())
		}
	})
	for _, code := range []int{401, 403} {
		t.Run(fmt.Sprintf("%d backs off 10 minutes", code), func(t *testing.T) {
			h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
			h.remote.getErr = &sdk.APIStatusError{StatusCode: code}
			mustStartup(t, h.rc)
			h.poll(t)
			if h.remote.getCount() != 1 {
				t.Fatalf("expected no fetch during the backoff, got %d", h.remote.getCount())
			}
			h.clock.Advance(remoteAuthBackoff + time.Second)
			h.poll(t)
			if h.remote.getCount() != 2 {
				t.Fatalf("expected a retry after the backoff, got %d", h.remote.getCount())
			}
		})
	}
	t.Run("409 pauses reports for an hour while polling continues", func(t *testing.T) {
		h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
		h.remote.publish(0, `{}`)
		h.remote.reportErr = func(int, agentconfig.Report) error { return &sdk.APIStatusError{StatusCode: 409} }
		mustStartup(t, h.rc)
		h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
		h.poll(t)
		if h.remote.reportCount() != 1 {
			t.Fatalf("expected reports paused after a 409, got %d", h.remote.reportCount())
		}
		if h.remote.getCount() != 2 {
			t.Fatalf("polling must continue after a 409, got %d gets", h.remote.getCount())
		}
		h.clock.Advance(reportConflictBackoff + time.Second)
		h.poll(t)
		if h.remote.reportCount() != 2 {
			t.Fatalf("expected a report after the 1h pause, got %d", h.remote.reportCount())
		}
	})
	t.Run("413 resends truncated", func(t *testing.T) {
		h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
		h.remote.publish(0, `{}`)
		h.remote.reportErr = func(n int, r agentconfig.Report) error {
			if !r.Truncated {
				return &sdk.APIStatusError{StatusCode: 413}
			}
			return nil
		}
		mustStartup(t, h.rc)
		if h.remote.reportCount() != 2 || !h.remote.lastReport(t).Truncated {
			t.Fatalf("expected a truncated resend, got %d reports", h.remote.reportCount())
		}
	})
}

func TestReport_OversizedIsTruncated(t *testing.T) {
	big := strings.Repeat("# padding\n", 30000) // ~300 KiB per module
	modules := map[string]string{}
	for i := 0; i < 14; i++ {
		modules[fmt.Sprintf("m%02d.rego", i)] = "package compliance_framework.m\n" + big
	}
	report := agentconfig.Report{Mode: "apply_safe", Status: "applied"}
	doc := agentconfig.Config{PolicyBundles: map[string]*agentconfig.PolicyBundle{"b": {Modules: modules}}}
	report.Base = marshalRaw(doc)
	report.Effective = marshalRaw(doc)
	body, _, err := fitReport(&report, false)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated || len(body) > agentconfig.MaxReportBytes {
		t.Fatalf("expected a truncated report under the limit, got truncated=%v size=%d", report.Truncated, len(body))
	}
	if !strings.Contains(string(report.Effective), `"sha256:`) {
		t.Fatalf("expected modules to be replaced by digests")
	}
}

func TestReport_FileWarningStatusApplied(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", "")+`
  bad:
    source: ./plugin-bad
    schedule: "not a cron"
`)
	mustStartup(t, h.rc)
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusApplied || len(r.Warnings) != 1 || r.Warnings[0].Path != "/plugins/bad/schedule" {
		t.Fatalf("expected an applied report with one warning, got %+v", r)
	}
}

func TestSetAgentVersion(t *testing.T) {
	defer SetAgentVersion("dev")
	SetAgentVersion("v1.2.3")
	if agentVersion != "v1.2.3" {
		t.Fatalf("got %q", agentVersion)
	}
	SetAgentVersion("")
	if agentVersion == "" {
		t.Fatal("empty version must fall back")
	}
}

// --- G3: pull and apply ---

func TestApply_BadOverlayKeepsOldConfig(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	first := mustStartup(t, h.rc)
	h.remote.publish(2, `{"plugins":{"ssh":{"schedule":"bad cron"}}}`)
	if got := h.poll(t); got != first {
		t.Fatal("a bad overlay must keep the running config")
	}
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusRejected || r.Reason != agentconfig.ReasonInvalidConfig || *r.AttemptedRevision != 2 || *r.AppliedRevision != 1 {
		t.Fatalf("unexpected report %+v", r)
	}
}

func TestApply_DownloadFailureKeepsOldConfig(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	first := mustStartup(t, h.rc)
	h.pf.setErr(errors.New("registry down"))
	h.remote.publish(2, `{"plugins":{"ssh":{"schedule":"*/7 * * * *"}}}`)
	if got := h.poll(t); got != first {
		t.Fatal("a download failure must keep the running config")
	}
	if r := h.remote.lastReport(t); r.Status != agentconfig.StatusFailed || r.Reason != agentconfig.ReasonDownloadFailed {
		t.Fatalf("unexpected report %+v", r)
	}
}

func TestApply_FailedBackoff(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(0, `{}`)
	mustStartup(t, h.rc)
	h.pf.setErr(errors.New("registry down"))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/7 * * * *"}}}`)
	h.poll(t)
	calls := h.pf.callCount()
	h.clock.Advance(30 * time.Second)
	h.poll(t)
	if h.pf.callCount() != calls {
		t.Fatal("a failed revision must not be retried before 1m")
	}
	h.clock.Advance(31 * time.Second)
	h.poll(t)
	if h.pf.callCount() != calls+1 {
		t.Fatal("expected a retry after 1m")
	}
	for i := 0; i < 6; i++ { // 2m, 4m, 8m, 10m, 10m...
		h.clock.Advance(failedRetryMax + time.Second)
		h.poll(t)
	}
	if h.rc.failedInterval != failedRetryMax {
		t.Fatalf("backoff must cap at %s, got %s", failedRetryMax, h.rc.failedInterval)
	}
}

func TestApply_ClassifyGate(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		flags   string
		overlay string
		status  string
		reason  string
	}{
		{"api.url is forbidden", "apply_safe", "", `{"api":{"url":"http://evil"}}`, "rejected", "forbidden-changes"},
		{"api.url is forbidden in apply_all", "apply_all", "", `{"api":{"url":"http://evil"}}`, "rejected", "forbidden-changes"},
		{"new untrusted source is unsafe", "apply_safe", "", `{"plugins":{"ssh":{"source":"ghcr.io/other/plugin:v1"}}}`, "rejected", "unsafe-changes"},
		{"config change is unsafe by default", "apply_safe", "", `{"plugins":{"ssh":{"config":{"host":"other"}}}}`, "rejected", "unsafe-changes"},
		{"schedule-only change applies", "apply_safe", "", `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`, "applied", ""},
		{"trusted source applies", "apply_safe", "", `{"plugins":{"ssh":{"source":"ghcr.io/trusted/plugin:v2"}}}`, "applied", ""},
		{"unqualified overridable flag", "apply_safe", `"host"`, `{"plugins":{"ssh":{"config":{"host":"other"}}}}`, "applied", ""},
		{"plugin:key overridable flag", "apply_safe", `"ssh:host"`, `{"plugins":{"ssh":{"config":{"host":"other"}}}}`, "applied", ""},
		{"other plugin's flag does not match", "apply_safe", `"github:host"`, `{"plugins":{"ssh":{"config":{"host":"other"}}}}`, "rejected", "unsafe-changes"},
		{"star overridable flag", "apply_safe", `"*"`, `{"plugins":{"ssh":{"config":{"host":"other"}}}}`, "applied", ""},
		{"trusted new plugin with overridable keys", "apply_safe", `"*"`, `{"plugins":{"new":{"source":"ghcr.io/trusted/new:v1","config":{"a":"b"}}}}`, "applied", ""},
		{"new env ref in an overridable key", "apply_safe", `"*"`, `{"plugins":{"ssh":{"config":{"host":"${env:HOST}"}}}}`, "rejected", "unsafe-changes"},
		{"unsafe applies in apply_all", "apply_all", "", `{"plugins":{"ssh":{"config":{"host":"other"}}}}`, "applied", ""},
		{"R27 non-string config value", "apply_all", "", `{"plugins":{"ssh":{"config":{"port":2222}}}}`, "rejected", "invalid-type"},
		{"R27 unknown field", "apply_all", "", `{"evidence_capture":{}}`, "rejected", "unknown-field"},
		{"R28 mixed-case plugin name", "apply_all", "", `{"plugins":{"GitHub":{"source":"ghcr.io/trusted/gh:v1"}}}`, "rejected", "invalid-config"},
		{"R28 mixed-case bundle name", "apply_all", "", `{"policy_bundles":{"MyBundle":{"modules":{"a.rego":"package compliance_framework.a"}}}}`, "rejected", "invalid-config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newRemoteHarness(t, remoteConfig(tt.mode, tt.flags))
			h.remote.publish(1, tt.overlay)
			mustStartup(t, h.rc)
			r := h.remote.lastReport(t)
			if r.Status != tt.status || r.Reason != tt.reason {
				t.Fatalf("got %s/%s (%v), want %s/%s", r.Status, r.Reason, derefString(r.Error), tt.status, tt.reason)
			}
			if tt.reason == "unsafe-changes" && len(r.Unsafe) == 0 {
				t.Fatal("expected the unsafe changes to be listed")
			}
		})
	}
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestApply_404FallsBackToCacheThenFile(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	mustStartup(t, h.rc)

	h.remote.overlay = nil // the API now answers 404
	restarted := h.newReconciler()
	active := mustStartup(t, restarted)
	if active.overlay == nil || active.overlay.Revision != 1 {
		t.Fatalf("expected the cached overlay after a 404, got %+v", active.overlay)
	}

	if err := os.Remove(filepath.Join(h.dir, "state", "remote-config.json")); err != nil {
		t.Fatal(err)
	}
	fileOnly := mustStartup(t, h.newReconciler())
	if fileOnly.overlay != nil {
		t.Fatalf("expected the file only without a cache, got %+v", fileOnly.overlay)
	}
}

func TestApply_OpaqueETag(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(3, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	mustStartup(t, h.rc)
	firstETag := h.remote.etag
	h.poll(t)
	if got := h.remote.gets[len(h.remote.gets)-1]; got != firstETag {
		t.Fatalf("If-None-Match must be the raw ETag %q, got %q", firstETag, got)
	}
	// The API is reset and reuses revision 3 with another overlay and a new ETag.
	h.remote.publish(3, `{"plugins":{"ssh":{"schedule":"*/9 * * * *"}}}`)
	if got := *h.poll(t).runtime.Plugins["ssh"].Schedule; got != "*/9 * * * *" {
		t.Fatalf("a new ETag with a reused revision must be re-evaluated, got schedule %q", got)
	}
	for _, sent := range h.remote.gets {
		if sent == "3" || sent == `"3"` {
			t.Fatalf("the agent must never build an ETag from a revision, sent %q", sent)
		}
	}
}

func TestCache_IdentityCorruptionAndMode(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	mustStartup(t, h.rc)
	cachePath := filepath.Join(h.dir, "state", "remote-config.json")
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode = %v, want 0600", info.Mode().Perm())
	}

	t.Run("identity mismatch discards the cache", func(t *testing.T) {
		store := agentstate.Open(filepath.Join(h.dir, "state"), nil)
		c, err := store.LoadCache(agentstate.Identity{APIURL: "http://other", ClientID: "x"})
		if err != nil || c.Applied != nil || c.Fetched != nil {
			t.Fatalf("expected an empty cache, got %+v, %v", c, err)
		}
	})

	t.Run("corruption is reported and the agent continues", func(t *testing.T) {
		raw, err := os.ReadFile(cachePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cachePath, []byte(strings.Replace(string(raw), `"revision": 1`, `"revision": 9`, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		h.remote.overlay = nil // 404: nothing to fetch
		active := mustStartup(t, h.newReconciler())
		if active.overlay != nil {
			t.Fatalf("a corrupt cache must not be applied, got %+v", active.overlay)
		}
		if r := h.remote.lastReport(t); r.Status != agentconfig.StatusFailed || r.Reason != agentconfig.ReasonCacheCorrupt {
			t.Fatalf("expected failed/cache-corrupt, got %s/%s", r.Status, r.Reason)
		}
	})
}

func TestApply_RejectedRevisionMemory(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"source":"ghcr.io/other/plugin:v1"}}}`)
	mustStartup(t, h.rc)
	if r := h.remote.lastReport(t); r.Reason != agentconfig.ReasonUnsafeChanges {
		t.Fatalf("expected unsafe-changes, got %s", r.Reason)
	}
	calls := h.pf.callCount()
	h.poll(t)
	h.poll(t)
	if h.pf.callCount() != calls {
		t.Fatalf("a remembered rejection must not be re-prepared (%d prefetches)", h.pf.callCount()-calls)
	}
	// A base edit that makes the source "already used" re-classifies and applies.
	h.writeConfig(t, remoteConfig("apply_safe", "")+`
  other:
    source: ghcr.io/other/plugin:v1
`)
	h.rc.reconcile(context.Background(), triggerFile)
	if next := h.rc.takePending(); next == nil || next.overlay == nil || next.overlay.Revision != 1 {
		t.Fatalf("expected revision 1 to apply after the base edit, got %+v", next)
	}
}

func TestStartupLadder(t *testing.T) {
	t.Run("fetched wins", func(t *testing.T) {
		h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
		h.remote.publish(2, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
		if a := mustStartup(t, h.rc); a.overlay == nil || a.overlay.Revision != 2 {
			t.Fatalf("got %+v", a.overlay)
		}
	})
	t.Run("rejected fetched falls back to applied", func(t *testing.T) {
		h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
		h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
		mustStartup(t, h.rc)
		h.remote.publish(2, `{"plugins":{"ssh":{"source":"ghcr.io/other/plugin:v1"}}}`)
		a := mustStartup(t, h.newReconciler())
		if a.overlay == nil || a.overlay.Revision != 1 {
			t.Fatalf("expected the applied revision 1, got %+v", a.overlay)
		}
		r := h.remote.lastReport(t)
		if r.Status != agentconfig.StatusRejected || *r.AttemptedRevision != 2 || *r.AppliedRevision != 1 {
			t.Fatalf("unexpected report %+v", r)
		}
	})
	t.Run("failing fetched and applied fall back to the file", func(t *testing.T) {
		h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
		h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
		mustStartup(t, h.rc)
		h.remote.publish(2, `{"plugins":{"ssh":{"schedule":"*/7 * * * *"}}}`)
		h.pf.setErr(errors.New("registry down"))
		restarted := h.newReconciler()
		if _, err := restarted.startup(context.Background()); err == nil {
			t.Fatal("when even the file cannot be prepared startup must fail")
		}
		h.pf.setErr(nil)
	})
	t.Run("unusable file fails", func(t *testing.T) {
		h := newRemoteHarness(t, "api: {}\n")
		if _, err := h.rc.startup(context.Background()); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestEnvPlaceholders(t *testing.T) {
	// ${env:} is only resolved in plugins.*.config (R24): in the file's policy_data it is a
	// literal passed through unchanged with a warning (R34, as on main), and an overlay using
	// it there is rejected.
	lenient := newRemoteHarness(t, remoteConfig("apply_all", "")+`
    policy_data:
      url: "${env:NOT_RESOLVED}"
`)
	started, err := lenient.rc.startup(context.Background())
	if err != nil {
		t.Fatalf("a file policy_data placeholder must not be fatal: %v", err)
	}
	if got := started.runtime.Plugins["ssh"].PolicyData["url"]; got != "${env:NOT_RESOLVED}" {
		t.Fatalf("policy_data must be passed through unchanged, got %v", got)
	}
	if r := lenient.remote.lastReport(t); len(r.Warnings) != 1 || r.Warnings[0].Code != agentconfig.FieldCodeEnvLocation {
		t.Fatalf("expected one env-location warning, got %+v", r.Warnings)
	}

	h := newRemoteHarness(t, remoteConfig("apply_all", ""))
	env := map[string]string{"HOST": "db.internal", "PORT": "5432"}
	h.rc.lookupEnv = func(n string) (string, bool) { v, ok := env[n]; return v, ok }
	h.remote.publish(1, `{"plugins":{"ssh":{"policy_data":{"url":"${env:HOST}"}}}}`)
	mustStartup(t, h.rc)
	if r := h.remote.lastReport(t); r.Status != agentconfig.StatusRejected || r.Reason != agentconfig.ReasonInvalidConfig {
		t.Fatalf("expected an overlay policy_data placeholder to be rejected, got %s/%s", r.Status, r.Reason)
	}

	h.remote.publish(2, `{"plugins":{"ssh":{"config":{"host":"${env:HOST}","dsn":"pg://${env:HOST}:${env:PORT}/db"}}}}`)
	active := h.poll(t)
	cfg := active.runtime.Plugins["ssh"].Config
	if cfg["host"] != "db.internal" || cfg["dsn"] != "pg://db.internal:5432/db" {
		t.Fatalf("placeholders not resolved whole/embedded: %#v", cfg)
	}
	if !strings.Contains(string(h.remote.lastReport(t).Effective), "${env:HOST}") {
		t.Fatal("the report must carry the unresolved placeholder")
	}
	digest := active.digest
	env["HOST"] = "rotated"
	restarted := h.newReconciler()
	restarted.lookupEnv = h.rc.lookupEnv
	if again := mustStartup(t, restarted); again.digest != digest || again.overlay == nil {
		t.Fatal("the digest must not change when an env value changes")
	}

	delete(env, "PORT")
	h.remote.publish(3, `{"plugins":{"ssh":{"config":{"host":"${env:HOST}","dsn":"pg://${env:PORT}"}}}}`)
	h.rc.lookupEnv = func(n string) (string, bool) { v, ok := env[n]; return v, ok }
	h.poll(t)
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusFailed || r.Reason != agentconfig.ReasonEnvMissing {
		t.Fatalf("expected failed/env-missing, got %s/%s", r.Status, r.Reason)
	}
	if !strings.Contains(*r.Error, "PORT") || strings.Contains(*r.Error, "rotated") {
		t.Fatalf("the error must name the variable, never values: %q", *r.Error)
	}
}

// TestEnvPlaceholders_FileOriginUnsetIsWarning pins R60: an unset variable the FILE references
// is a warning and the literal reaches the plugin unchanged (as on main); an unset variable the
// overlay introduces still fails with failed/env-missing.
func TestEnvPlaceholders_FileOriginUnsetIsWarning(t *testing.T) {
	content := strings.Replace(remoteConfig("apply_all", ""), "token: t0ken", "token: \"${env:UNSET_TOKEN}\"\n      dsn: \"pg://${env:DB_HOST}/x\"", 1)
	h := newRemoteHarness(t, content)
	env := map[string]string{"DB_HOST": "db.internal"}
	h.rc.lookupEnv = func(n string) (string, bool) { v, ok := env[n]; return v, ok }
	h.remote.publish(1, `{}`)

	active := mustStartup(t, h.rc)
	cfg := active.runtime.Plugins["ssh"].Config
	if cfg["token"] != "${env:UNSET_TOKEN}" || cfg["dsn"] != "pg://db.internal/x" {
		t.Fatalf("expected the unset literal unchanged and the set one resolved, got %#v", cfg)
	}
	r := h.remote.lastReport(t)
	if r.Status != agentconfig.StatusApplied || len(r.Warnings) != 1 || r.Warnings[0].Path != "/plugins/ssh/config/token" || r.Warnings[0].Code != agentconfig.FieldCodeEnvMissing {
		t.Fatalf("expected applied with one env-missing warning, got %s %+v", r.Status, r.Warnings)
	}

	h.remote.publish(2, `{"plugins":{"ssh":{"config":{"extra":"${env:NEW_UNSET}"}}}}`)
	h.poll(t)
	if r := h.remote.lastReport(t); r.Status != agentconfig.StatusFailed || r.Reason != agentconfig.ReasonEnvMissing {
		t.Fatalf("an overlay-introduced unset variable must fail with env-missing, got %s/%s", r.Status, r.Reason)
	}

	// Per (pointer, variable): the overlay rewrites the value but the variable is the file's.
	h.remote.publish(3, `{"plugins":{"ssh":{"config":{"token":"x-${env:UNSET_TOKEN}"}}}}`)
	next := h.poll(t)
	if got := next.runtime.Plugins["ssh"].Config["token"]; got != "x-${env:UNSET_TOKEN}" || next.appliedRevision() == nil || *next.appliedRevision() != 3 {
		t.Fatalf("expected revision 3 applied with the literal unchanged, got %q", got)
	}
}

func TestOneShot_FetchApplyReportRun(t *testing.T) {
	h := newRemoteHarness(t, strings.Replace(remoteConfig("apply_safe", ""), "daemon: true", "daemon: false", 1))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	active, err := h.rc.startup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if h.remote.reportCount() != 1 || h.remote.lastReport(t).Daemon {
		t.Fatalf("one-shot must report once with daemon=false before running")
	}
	runs := 0
	err = h.rc.run(active, func(_ context.Context, cfg *agentConfig) error {
		runs++
		if *cfg.Plugins["ssh"].Schedule != "*/5 * * * *" {
			t.Fatalf("the overlay was not applied")
		}
		return nil
	})
	if err != nil || runs != 1 {
		t.Fatalf("one-shot must run once and exit: runs=%d err=%v", runs, err)
	}
}

func TestReconciler_RaceInterleavedFileEventsAndPolls(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/1 * * * *"}}}`)
	h.rc.now = time.Now
	active, err := h.rc.startup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	running := 0
	maxRunning := 0
	var last *agentConfig
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- h.rc.run(active, func(ctx context.Context, cfg *agentConfig) error {
			mu.Lock()
			running++
			maxRunning = max(maxRunning, running)
			last = cfg
			mu.Unlock()
			defer func() {
				mu.Lock()
				running--
				mu.Unlock()
			}()
			select {
			case <-ctx.Done():
				return nil
			case <-stop:
				return errStopRun
			}
		})
	}()
	t.Cleanup(func() {
		// Stop rc.run (it returns once the run and its fallback both stop) so the goroutine
		// does not leak into other tests.
		close(stop)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("rc.run did not return")
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 2; i <= 200; i++ {
		h.remote.publish(int64(i), fmt.Sprintf(`{"plugins":{"ssh":{"schedule":"*/%d * * * *"}}}`, i%59+1))
		h.rc.reconcile(ctx, triggerPoll)
		if i%10 == 0 {
			h.rc.reconcile(ctx, triggerFile)
		}
	}
	want := fmt.Sprintf("*/%d * * * *", 200%59+1)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := last != nil && *last.Plugins["ssh"].Schedule == want
		mu.Unlock()
		if ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if maxRunning != 1 {
		t.Fatalf("expected exactly one active run at a time, saw %d", maxRunning)
	}
	if last == nil || *last.Plugins["ssh"].Schedule != want {
		t.Fatalf("the last revision must win")
	}
}

// TestApply_NoOpRevisionAdoptedWithoutRestart: a revision whose effective config equals the
// running one is recorded as applied without a restart, and is not re-prepared every poll.
func TestApply_NoOpRevisionAdoptedWithoutRestart(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	first := mustStartup(t, h.rc)

	// verbosity 0 equals the base: the effective config does not change.
	h.remote.publish(2, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}},"verbosity":0}`)
	calls := h.pf.callCount()
	var cur *candidate
	for i := 0; i < 3; i++ {
		cur = h.poll(t)
	}
	if got := h.pf.callCount() - calls; got != 1 {
		t.Fatalf("a no-op revision must be prepared once, got %d prefetches", got)
	}
	if cur.runtime != first.runtime {
		t.Fatal("a no-op revision must not restart the running configuration")
	}
	if rev := cur.runtime.syncInfo().AppliedRevision; rev != 2 {
		t.Fatalf("the heartbeat/evidence must show applied revision 2, got %d", rev)
	}
	if r := h.remote.lastReport(t); r.Status != agentconfig.StatusApplied || r.AppliedRevision == nil || *r.AppliedRevision != 2 {
		t.Fatalf("the report must show applied revision 2, got %+v", r)
	}

	// A comment-only file edit is adopted the same way.
	h.writeConfig(t, "# a comment\n"+remoteConfig("apply_safe", ""))
	h.rc.reconcile(context.Background(), triggerFile)
	calls = h.pf.callCount()
	for i := 0; i < 3; i++ {
		cur = h.poll(t)
	}
	if h.pf.callCount() != calls || cur.runtime != first.runtime {
		t.Fatalf("a comment-only edit must not be re-prepared every poll (%d prefetches) nor restart", h.pf.callCount()-calls)
	}
}

// TestApply_RejectedAppliedOverlayNotRePrepared: after a file edit makes the applied overlay
// invalid, the remembered rejection keeps last-known-good instead of re-preparing every poll.
func TestApply_RejectedAppliedOverlayNotRePrepared(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", `"host"`))
	var logs bytes.Buffer
	h.rc.logger = hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn})
	h.remote.publish(1, `{"plugins":{"ssh":{"config":{"host":"other"}}}}`)
	first := mustStartup(t, h.rc)
	if first.overlay == nil {
		t.Fatal("revision 1 must apply while host is overridable")
	}

	h.writeConfig(t, remoteConfig("apply_safe", "")) // host is no longer overridable
	h.rc.reconcile(context.Background(), triggerFile)
	if r := h.remote.lastReport(t); r.Status != agentconfig.StatusRejected || r.Reason != agentconfig.ReasonUnsafeChanges {
		t.Fatalf("expected rejected/unsafe-changes, got %s/%s", r.Status, r.Reason)
	}
	prepares := strings.Count(logs.String(), "Could not apply the configuration")
	for i := 0; i < 3; i++ {
		if got := h.poll(t); got != first {
			t.Fatal("the last-known-good configuration must keep running")
		}
	}
	if got := strings.Count(logs.String(), "Could not apply the configuration") - prepares; got != 0 {
		t.Fatalf("a remembered rejection must not be re-prepared, got %d prepares", got)
	}
}

// TestApply_EmptyETagDoesNotBlockLaterRevisions: without an ETag, revisions are told apart by
// revision + overlay bytes.
func TestApply_EmptyETagDoesNotBlockLaterRevisions(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"source":"ghcr.io/other/plugin:v1"}}}`)
	h.remote.etag = ""
	mustStartup(t, h.rc)
	if r := h.remote.lastReport(t); r.Reason != agentconfig.ReasonUnsafeChanges {
		t.Fatalf("expected unsafe-changes, got %s", r.Reason)
	}
	h.remote.publish(2, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	h.remote.etag = ""
	if got := h.poll(t); got.overlay == nil || got.overlay.Revision != 2 {
		t.Fatalf("revision 2 must apply despite the empty ETag, got %+v", got.overlay)
	}
}

// TestApply_RunFailureNotifiesAfterFallbackIsBound: onRunFailed sees the fallback as current,
// so the applied overlay reverts to it and the report describes it.
func TestApply_RunFailureNotifiesAfterFallbackIsBound(t *testing.T) {
	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	active, err := h.rc.startup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- h.rc.run(active, func(ctx context.Context, cfg *agentConfig) error {
			if *cfg.Plugins["ssh"].Schedule == "*/7 * * * *" {
				return errors.New("failed to start")
			}
			select {
			case <-ctx.Done():
				return nil
			case <-stop:
				return errStopRun
			}
		})
	}()
	h.remote.publish(2, `{"plugins":{"ssh":{"schedule":"*/7 * * * *"}}}`)
	h.rc.reconcile(context.Background(), triggerPoll)

	var failedRun *candidate
	select {
	case failedRun = <-h.rc.runFailed:
	case <-time.After(5 * time.Second):
		t.Fatal("the run failure was never notified")
	}
	if cur := h.rc.current(); cur == nil || cur.overlay == nil || cur.overlay.Revision != 1 {
		t.Fatalf("the fallback must be bound before the notification, current is %+v", cur)
	}
	h.rc.onRunFailed(context.Background(), failedRun)
	if a := h.rc.cache.Applied; a == nil || a.Revision != 1 {
		t.Fatalf("the applied overlay must revert to revision 1, got %+v", a)
	}
	if r := h.remote.lastReport(t); r.Status != agentconfig.StatusFailed || r.AppliedRevision == nil || *r.AppliedRevision != 1 {
		t.Fatalf("the failure report must describe the fallback, got %+v", r)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return")
	}
}

// TestApply_PrefetchIsBounded: a hanging registry does not stall the reconciler.
func TestApply_PrefetchIsBounded(t *testing.T) {
	old := prepareNetworkTimeout
	prepareNetworkTimeout = 50 * time.Millisecond
	t.Cleanup(func() { prepareNetworkTimeout = old })

	h := newRemoteHarness(t, remoteConfig("apply_safe", ""))
	h.remote.publish(1, `{"plugins":{"ssh":{"schedule":"*/5 * * * *"}}}`)
	first := mustStartup(t, h.rc)
	h.pf.setBlock(true)
	h.remote.publish(2, `{"plugins":{"ssh":{"schedule":"*/7 * * * *"}}}`)
	start := time.Now()
	if got := h.poll(t); got != first {
		t.Fatal("a hung download must keep the running config")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("prepare was not bounded: %s", time.Since(start))
	}
	if r := h.remote.lastReport(t); r.Status != agentconfig.StatusFailed || r.Reason != agentconfig.ReasonDownloadFailed {
		t.Fatalf("expected failed/download-failed, got %s/%s", r.Status, r.Reason)
	}
}
