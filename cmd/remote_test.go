package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/compliance-framework/agent/internal/agentstate"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/sdk"
	"github.com/google/uuid"
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
	rc.newRemote = func(agentconfig.Config) remoteAPI { return h.remote }
	rc.now = h.clock.Now
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
	rc.bind(active, func() {})
	return active
}

// poll runs one poll trigger and returns the candidate now running (the pending swap, if any).
func (h *remoteHarness) poll(t *testing.T) *candidate {
	t.Helper()
	h.rc.reconcile(context.Background(), triggerPoll)
	if next := h.rc.takePending(); next != nil {
		h.rc.bind(next, func() {})
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
      endpoint: https://bot:hunter2@git.example
`)
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
		if strings.Contains(s, "hunter2") {
			t.Fatalf("a password in a URL must be masked by value: %s", s)
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
	if active := mustStartup(t, rotated); active.digest != r.EffectiveDigest {
		t.Fatalf("digest changed when the env value rotated: %s vs %s", active.digest, r.EffectiveDigest)
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
	// config is a declared document of about n bytes.
	config := func(n int) json.RawMessage {
		return marshalRaw(agentconfig.Config{Plugins: map[string]*agentconfig.Plugin{
			"ssh": {Source: "ghcr.io/x/ssh:v1", Config: map[string]string{"blob": strings.Repeat("x", n)}},
		}})
	}
	// A report under the target is sent whole.
	report := agentconfig.Report{Mode: "apply_safe", Status: "applied", Base: config(1 << 19), Effective: config(1 << 19)}
	body, _, err := fitReport(&report, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Truncated || len(body) > reportTargetBytes || string(report.Base) == "{}" {
		t.Fatalf("expected the report kept whole, got truncated=%v size=%d", report.Truncated, len(body))
	}

	// An oversized one drops base.
	report = agentconfig.Report{Mode: "apply_safe", Status: "applied", Base: config(2 << 20), Effective: config(2 << 20)}
	body, _, err = fitReport(&report, false)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Truncated || len(body) > agentconfig.MaxReportBytes || string(report.Base) != "{}" {
		t.Fatalf("expected base dropped and a report under the limit, got truncated=%v size=%d", report.Truncated, len(body))
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
