package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/uuid"
)

func TestReportStartupFailureMarksPluginsAndSendsEvidence(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	ar := NewAgentRunner()
	ar.httpClient = newTestHTTPClient(func(r *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		return jsonResponse(http.StatusCreated, ""), nil
	})
	cfg := newTestAgentConfig("http://example.test", nil)
	ar.ReportStartupFailure(context.Background(), cfg, &downloadError{source: "ghcr.io/some-plugin:v1", err: errors.New("registry down")})

	if snap := ar.pluginRunSnapshot(); !slices.Contains(snap.Failed, "test-plugin") || !strings.Contains(snap.Errors["test-plugin"], "registry down") {
		t.Fatalf("the plugin using the failed source must be marked failed, got %+v", snap)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || !strings.Contains(bodies[0], "Plugins with errors: test-plugin") {
		t.Fatalf("expected one startup-failure evidence naming the failed plugin, got %d: %v", len(bodies), bodies)
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

// TestRunDaemonSignalDuringReloadDrainExits: a SIGTERM that arrives while a reload drains is
// not lost; it exits (R33: SIGTERM keeps its 30s) instead of waiting out the 5m drain.
func TestRunDaemonSignalDuringReloadDrainExits(t *testing.T) {
	oldStop := daemonCronStopTimeout
	daemonCronStopTimeout = 100 * time.Millisecond
	t.Cleanup(func() { daemonCronStopTimeout = oldStop })

	schedule := "@every 1s"
	disabled := false
	ar := NewAgentRunner()
	ar.UpdateConfig(&agentConfig{
		Daemon:        true,
		ApiConfig:     &apiConfig{Url: "http://127.0.0.1:1"},
		AgentEvidence: &agentEvidenceConfig{Enabled: &disabled},
		Plugins:       map[string]*agentPlugin{"slow": {Source: "/tmp/slow", Schedule: &schedule}},
	})
	sigCh := make(chan chan<- os.Signal, 1)
	ar.notifySignals = func(c chan<- os.Signal) { sigCh <- c }
	exited := make(chan int, 1)
	ar.exitFunc = func(code int) { exited <- code }
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	ar.runPluginFunc = func(context.Context, string, *agentPlugin) error {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release // outlives the test's patience: only the signal can end the drain
		return nil
	}
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ar.runDaemon(ctx) }()
	sigs := <-sigCh
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("plugin never started")
	}
	cancel() // reload: the drain waits for the blocked run
	time.Sleep(50 * time.Millisecond)
	sigs <- syscall.SIGTERM

	select {
	case code := <-exited:
		if code != 0 {
			t.Fatalf("exit code %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a SIGTERM during the reload drain was lost")
	}
	<-done
}
