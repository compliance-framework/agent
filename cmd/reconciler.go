package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/compliance-framework/agent/internal/agentstate"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// fileDebounce coalesces bursts of config file events (editors write in several steps).
var fileDebounce = 500 * time.Millisecond

// candidate is a complete, validated configuration that is ready to run. The reconciler builds
// it BEFORE cancelling the running configuration (prepare-then-cancel, R32). It is immutable
// once built.
type candidate struct {
	base     *baseSnapshot
	declared agentconfig.Config // merged, ${env:} NOT resolved: reported and digested
	runtime  *agentConfig       // resolved, enabled-only, skipped plugins removed
	digest   string             // agentconfig.Digest(declared, base.redactOpts()...) (R55)
	// identity changes whenever anything that affects the runtime changes, including the
	// values the digest masks or omits (api block, secrets). It never leaves the process.
	identity string
	warnings []agentconfig.FieldError // R34 file-origin warnings
}

// applyError is why a candidate could not be prepared. Status is agentconfig.StatusRejected
// or agentconfig.StatusFailed and Reason is one of agentconfig.Reasons.
type applyError struct {
	Status       string
	Reason       string
	Err          error
	Unsafe       []agentconfig.Change
	PolicyErrors []agentconfig.PolicyError
}

func (e *applyError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Status, e.Reason)
	}
	return fmt.Sprintf("%s: %s: %v", e.Status, e.Reason, e.Err)
}

func (e *applyError) Unwrap() error { return e.Err }

// prefetcher is the part of AgentRunner the reconciler drives (a test seam).
type prefetcher interface {
	Prefetch(ctx context.Context, cfg *agentConfig) error
}

// runFunc runs one configuration until it is cancelled (daemon) or completes (one-shot).
type runFunc func(ctx context.Context, cfg *agentConfig) error

// reconciler is the single writer of the configuration state. File (and, from G3, remote)
// triggers are serialized in one goroutine: a trigger builds a complete candidate and only
// then cancels the running configuration; a failure tears nothing down.
type reconciler struct {
	cmd        *cobra.Command
	configPath string
	store      *agentstate.Store
	runner     prefetcher
	logger     hclog.Logger
	fileEvents chan struct{}

	mu        sync.Mutex // guards active, pending, cancelRun
	active    *candidate
	pending   *candidate
	cancelRun context.CancelFunc

	base *baseSnapshot // reconciler goroutine only
}

func newReconciler(cmd *cobra.Command, configPath string, store *agentstate.Store, runner prefetcher, logger hclog.Logger) *reconciler {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	return &reconciler{
		cmd:        cmd,
		configPath: configPath,
		store:      store,
		runner:     runner,
		logger:     logger.Named("reconciler"),
		fileEvents: make(chan struct{}, 1),
	}
}

// startup loads the file and prepares the first candidate. An error means the local
// configuration is unusable: the agent exits 1, as it always has (no panic).
func (rc *reconciler) startup(ctx context.Context) (*candidate, error) {
	base, err := loadBase(rc.cmd, rc.configPath)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	rc.base = base
	rc.logWarnings(base.warnings)
	cand, aerr := rc.prepare(ctx, base)
	if aerr != nil {
		return nil, aerr
	}
	return cand, nil
}

// prepare builds a candidate from a base. It never touches the running configuration.
func (rc *reconciler) prepare(ctx context.Context, base *baseSnapshot) (*candidate, *applyError) {
	declared := base.declared
	runtime, err := toRuntime(declared, nil, base.skip)
	if err != nil {
		return nil, &applyError{Status: agentconfig.StatusFailed, Reason: agentconfig.ReasonInvalidConfig, Err: err}
	}
	if err := rc.runner.Prefetch(ctx, runtime); err != nil {
		return nil, &applyError{Status: agentconfig.StatusFailed, Reason: agentconfig.ReasonDownloadFailed, Err: err}
	}
	digest := agentconfig.Digest(declared, base.redactOpts()...)
	runtime.sync = syncMeta{Digest: digest, Mode: runtime.remote.Mode}
	return &candidate{
		base:     base,
		declared: declared,
		runtime:  runtime,
		digest:   digest,
		identity: candidateIdentity(declared),
		warnings: base.warnings,
	}, nil
}

func candidateIdentity(c agentconfig.Config) string {
	raw, err := agentconfig.CanonicalJSON(c)
	if err != nil {
		raw = []byte(err.Error())
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// bind records the running candidate and how to cancel it. If a swap raced in between two
// runs, the new run is cancelled at once so the pending candidate is picked up.
func (rc *reconciler) bind(active *candidate, cancel context.CancelFunc) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.active = active
	rc.cancelRun = cancel
	if rc.pending != nil {
		cancel()
	}
}

// swap makes next the pending candidate and cancels the running one.
func (rc *reconciler) swap(next *candidate) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.pending = next
	if rc.cancelRun != nil {
		rc.cancelRun()
	}
}

func (rc *reconciler) takePending() *candidate {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	next := rc.pending
	rc.pending = nil
	return next
}

// current returns the candidate that is running, or about to run when a swap is pending.
func (rc *reconciler) current() *candidate {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.pending != nil {
		return rc.pending
	}
	return rc.active
}

// run drives run with the active candidate. A cancelled run (swap) picks up the pending
// candidate; a run that fails on its own falls back to the previous candidate once.
func (rc *reconciler) run(active *candidate, run runFunc) error {
	var previous *candidate
	for {
		runCtx, cancel := context.WithCancel(context.Background())
		rc.bind(active, cancel)
		runErr := run(runCtx, active.runtime)
		reload := runCtx.Err() != nil
		cancel()
		if runErr != nil && !reload {
			if previous != nil {
				rc.logger.Error("Configuration failed to run; falling back to the previous configuration", "error", runErr)
				rc.onRunFailed(active, runErr)
				active, previous = previous, nil
				continue
			}
			return runErr
		}
		if !active.runtime.Daemon {
			return runErr
		}
		next := rc.takePending()
		if next == nil {
			continue
		}
		previous, active = active, next
	}
}

// onRunFailed is called when a configuration that passed prepare fails to run on its own.
func (rc *reconciler) onRunFailed(_ *candidate, _ error) {}

// loop is the daemon's reconcile goroutine. It returns when ctx is done.
func (rc *reconciler) loop(ctx context.Context) {
	var debounce <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-rc.fileEvents:
			if debounce == nil {
				debounce = time.After(fileDebounce)
			}
		case <-debounce:
			debounce = nil
			rc.reconcileFile(ctx)
		}
	}
}

// reconcileFile handles a (debounced) config file change.
func (rc *reconciler) reconcileFile(ctx context.Context) {
	base, err := loadBase(rc.cmd, rc.configPath)
	if err != nil {
		rc.logger.Error("Config file is invalid; keeping the running configuration", "error", err)
		return
	}
	rc.base = base
	rc.logWarnings(base.warnings)
	cand, aerr := rc.prepare(ctx, base)
	if aerr != nil {
		rc.logger.Error("Could not prepare the new configuration; keeping the running configuration", "status", aerr.Status, "reason", aerr.Reason, "error", aerr.Err)
		return
	}
	if cur := rc.current(); cur != nil && cur.identity == cand.identity {
		rc.logger.Debug("Config file changed without changing the effective configuration")
		return
	}
	rc.logger.Info("Applying the new configuration")
	rc.swap(cand)
}

func (rc *reconciler) logWarnings(warnings []agentconfig.FieldError) {
	for _, w := range warnings {
		rc.logger.Warn("Ignoring a problem in the config file; the plugin is skipped", "path", w.Path, "error", w.Message)
	}
}

// signalFile queues a file event without blocking.
func (rc *reconciler) signalFile() {
	select {
	case rc.fileEvents <- struct{}{}:
	default:
	}
}

// watchFile watches the config file on a dedicated viper instance whose OnConfigChange only
// signals; loading always happens in the reconciler goroutine on a fresh viper. Known limit
// (R32 follow-up): viper stops watching after a Remove event.
func (rc *reconciler) watchFile() (stop func()) {
	var stopped atomic.Bool
	w := viper.New()
	w.SetConfigFile(rc.configPath)
	w.OnConfigChange(func(in fsnotify.Event) {
		if stopped.Load() {
			return
		}
		rc.logger.Debug("config file changed", "path", in.Name)
		rc.signalFile()
	})
	w.WatchConfig()
	return func() { stopped.Store(true) }
}
