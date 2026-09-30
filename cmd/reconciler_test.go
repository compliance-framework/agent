package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/compliance-framework/agent/internal/agentstate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
)

// fakePrefetcher records Prefetch calls and can be told to fail.
type fakePrefetcher struct {
	mu    sync.Mutex
	calls int
	err   error
}

func (f *fakePrefetcher) Prefetch(_ context.Context, _ *agentConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.err
}

func (f *fakePrefetcher) setErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func (f *fakePrefetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

const reconcilerTestConfig = `
daemon: true
api:
  url: http://localhost:8080
plugins:
  ssh:
    source: ./plugin-ssh
    schedule: "%s"
`

func newTestReconciler(t *testing.T, content string) (*reconciler, *fakePrefetcher, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	pf := &fakePrefetcher{}
	rc := newReconciler(AgentCmd(), path, agentstate.Open(filepath.Join(dir, "state"), nil), pf, nil)
	return rc, pf, path
}

func configWithSchedule(schedule string) string {
	return strings.Replace(reconcilerTestConfig, "%s", schedule, 1)
}

// runningReconciler starts rc.run with a fake run func that blocks until cancelled and
// records every config it was given.
type runRecorder struct {
	mu      sync.Mutex
	configs []*agentConfig
	started chan *agentConfig
	fail    func(cfg *agentConfig) error
}

func newRunRecorder() *runRecorder {
	return &runRecorder{started: make(chan *agentConfig, 100)}
}

func (r *runRecorder) run(ctx context.Context, cfg *agentConfig) error {
	r.mu.Lock()
	r.configs = append(r.configs, cfg)
	fail := r.fail
	r.mu.Unlock()
	r.started <- cfg
	if fail != nil {
		if err := fail(cfg); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

func (r *runRecorder) runCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.configs)
}

func waitStarted(t *testing.T, r *runRecorder) *agentConfig {
	t.Helper()
	select {
	case cfg := <-r.started:
		return cfg
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a run to start")
		return nil
	}
}

func expectNoStart(t *testing.T, r *runRecorder, within time.Duration) {
	t.Helper()
	select {
	case cfg := <-r.started:
		t.Fatalf("unexpected run started with %#v", cfg)
	case <-time.After(within):
	}
}

func startReconciler(t *testing.T, rc *reconciler, rec *runRecorder) {
	t.Helper()
	active, err := rc.startup(context.Background())
	if err != nil {
		t.Fatalf("startup: %v", err)
	}
	go func() { _ = rc.run(active, rec.run) }()
	waitStarted(t, rec)
}

func TestReconciler_InvalidFileAtStartupReturnsError(t *testing.T) {
	rc, _, _ := newTestReconciler(t, "daemon: true\nplugins:\n  ssh:\n    source: ./x\n")
	if _, err := rc.startup(context.Background()); err == nil || !strings.Contains(err.Error(), "/api") {
		t.Fatalf("expected a config file error, got %v", err)
	}
}

func TestReconciler_InvalidEditKeepsRunning(t *testing.T) {
	rc, pf, path := newTestReconciler(t, configWithSchedule("* * * * *"))
	rec := newRunRecorder()
	startReconciler(t, rc, rec)

	if err := os.WriteFile(path, []byte("daemon: true\nplugins: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rc.reconcile(context.Background(), triggerFile)
	expectNoStart(t, rec, 200*time.Millisecond)
	if pf.callCount() != 1 {
		t.Fatalf("an invalid file must not be prefetched, got %d calls", pf.callCount())
	}
}

func TestReconciler_ValidEditCancelsOnce(t *testing.T) {
	rc, _, path := newTestReconciler(t, configWithSchedule("* * * * *"))
	rec := newRunRecorder()
	startReconciler(t, rc, rec)

	if err := os.WriteFile(path, []byte(configWithSchedule("*/5 * * * *")), 0o600); err != nil {
		t.Fatal(err)
	}
	rc.reconcile(context.Background(), triggerFile)
	cfg := waitStarted(t, rec)
	if got := *cfg.Plugins["ssh"].Schedule; got != "*/5 * * * *" {
		t.Fatalf("new run has schedule %q", got)
	}
	// The same content again is not a change.
	rc.reconcile(context.Background(), triggerFile)
	expectNoStart(t, rec, 200*time.Millisecond)
	if rec.runCount() != 2 {
		t.Fatalf("expected exactly one reload, got %d runs", rec.runCount())
	}
}

func TestReconciler_PrefetchFailureDoesNotCancel(t *testing.T) {
	rc, pf, path := newTestReconciler(t, configWithSchedule("* * * * *"))
	rec := newRunRecorder()
	startReconciler(t, rc, rec)

	pf.setErr(errors.New("registry down"))
	if err := os.WriteFile(path, []byte(configWithSchedule("*/5 * * * *")), 0o600); err != nil {
		t.Fatal(err)
	}
	rc.reconcile(context.Background(), triggerFile)
	expectNoStart(t, rec, 200*time.Millisecond)
}

func TestReconciler_RunFailureFallsBackToPrevious(t *testing.T) {
	rc, _, path := newTestReconciler(t, configWithSchedule("* * * * *"))
	rec := newRunRecorder()
	rec.fail = func(cfg *agentConfig) error {
		if *cfg.Plugins["ssh"].Schedule == "*/5 * * * *" {
			return errors.New("cache wiped after prepare")
		}
		return nil
	}
	startReconciler(t, rc, rec)

	if err := os.WriteFile(path, []byte(configWithSchedule("*/5 * * * *")), 0o600); err != nil {
		t.Fatal(err)
	}
	rc.reconcile(context.Background(), triggerFile)
	if got := *waitStarted(t, rec).Plugins["ssh"].Schedule; got != "*/5 * * * *" {
		t.Fatalf("expected the new config to be tried, got %q", got)
	}
	if got := *waitStarted(t, rec).Plugins["ssh"].Schedule; got != "* * * * *" {
		t.Fatalf("expected a fallback to the previous config, got %q", got)
	}
}

func TestReconciler_RapidFileEventsRace(t *testing.T) {
	rc, _, path := newTestReconciler(t, configWithSchedule("* * * * *"))
	rec := newRunRecorder()
	rc.debounce = 5 * time.Millisecond
	startReconciler(t, rc, rec)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rc.loop(ctx)

	var writes atomic.Int32
	for i := 0; i < 50; i++ {
		schedule := "*/5 * * * *"
		if i%2 == 0 {
			schedule = "*/7 * * * *"
		}
		if err := os.WriteFile(path, []byte(configWithSchedule(schedule)), 0o600); err != nil {
			t.Fatal(err)
		}
		writes.Add(1)
		rc.signalFile()
		time.Sleep(time.Millisecond)
	}
	// The last write wins.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case cfg := <-rec.started:
			if *cfg.Plugins["ssh"].Schedule == "*/5 * * * *" {
				return
			}
		case <-deadline:
			t.Fatal("the last file write was never applied")
		}
	}
}

func TestReconciler_BindCancelsWhenSwapRacedIn(t *testing.T) {
	rc, _, _ := newTestReconciler(t, configWithSchedule("* * * * *"))
	rc.swap(&candidate{})
	ctx, cancel := context.WithCancel(context.Background())
	rc.bind(&candidate{}, cancel)
	if ctx.Err() == nil {
		t.Fatal("bind must cancel a run when a candidate is already pending")
	}
}

func TestPluginEnvironDropsAPICredentials(t *testing.T) {
	got := pluginEnviron([]string{
		"CCF_API_AUTH_CLIENT_SECRET=s",
		"ccf_api_auth_client_id=i",
		"AWS_REGION=eu-west-1",
		"CCF_INSTANCE_ID=abc",
		"PATH=/bin",
	})
	want := []string{"AWS_REGION=eu-west-1", "CCF_INSTANCE_ID=abc", "PATH=/bin"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("pluginEnviron = %v, want %v", got, want)
	}
}

func TestResolvePluginProtocols_CacheSurvivesLookupFailure(t *testing.T) {
	ar := NewAgentRunner()
	calls := 0
	ar.fetchAnnotations = func(context.Context, string, ...remote.Option) (map[string]string, error) {
		calls++
		if calls == 1 {
			return map[string]string{AnnotationProtocolVersionKey: "2"}, nil
		}
		return nil, errors.New("registry down")
	}
	newCfg := func() *agentConfig {
		return &agentConfig{Plugins: map[string]*agentPlugin{
			"p": {Source: "ghcr.io/example/plugin:v1", ProtocolVersion: DefaultProtocolVersion},
		}}
	}
	first := newCfg()
	ar.UpdateConfig(first)
	ar.resolvePluginProtocols(context.Background())
	second := newCfg()
	ar.UpdateConfig(second)
	ar.resolvePluginProtocols(context.Background())
	if got := second.Plugins["p"].ProtocolVersion; got != RunnerV2ProtocolVersion {
		t.Fatalf("expected the cached protocol 2 after a failing lookup, got %d", got)
	}
	if calls != 1 {
		t.Fatalf("expected one annotation lookup, got %d", calls)
	}
}

func TestHeartbeatUsesStableInstanceIDAcrossRuns(t *testing.T) {
	id := uuid.New()
	ar := NewAgentRunner(WithInstanceID(id))
	ar.UpdateConfig(newTestAgentConfig("http://example.test", nil))
	var seen []uuid.UUID
	var mu sync.Mutex
	ar.sendHeartbeatFunc = func(_ context.Context, got uuid.UUID) error {
		mu.Lock()
		seen = append(seen, got)
		mu.Unlock()
		return nil
	}
	for i := 0; i < 2; i++ {
		c, err := ar.setupHeartbeatCron(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Entries() {
			e.Job.Run()
		}
	}
	if len(seen) != 2 || seen[0] != id || seen[1] != id {
		t.Fatalf("heartbeats used %v, want %s twice", seen, id)
	}
}

func TestRunDaemonDrainsInFlightRunsOnReload(t *testing.T) {
	oldDrain := reloadDrainTimeout
	reloadDrainTimeout = 10 * time.Second
	t.Cleanup(func() { reloadDrainTimeout = oldDrain })

	schedule := "@every 1s"
	disabled := false
	ar := NewAgentRunner()
	ar.UpdateConfig(&agentConfig{
		Daemon:        true,
		ApiConfig:     &apiConfig{Url: "http://127.0.0.1:1"},
		AgentEvidence: &agentEvidenceConfig{Enabled: &disabled},
		Plugins:       map[string]*agentPlugin{"slow": {Source: "/tmp/slow", Schedule: &schedule}},
	})
	started := make(chan struct{}, 1)
	var finishedCleanly atomic.Bool
	ar.runPluginFunc = func(ctx context.Context, _ string, _ *agentPlugin) error {
		select {
		case started <- struct{}{}:
		default:
		}
		time.Sleep(300 * time.Millisecond)
		finishedCleanly.Store(ctx.Err() == nil)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ar.runDaemon(ctx) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("plugin never started")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runDaemon: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runDaemon did not return after the drain")
	}
	if !finishedCleanly.Load() {
		t.Fatal("the in-flight run was cut short by the reload")
	}
}
