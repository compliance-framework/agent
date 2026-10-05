package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
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

var (
	// failedRetryMin / failedRetryMax bound the retry of a failed/* revision.
	failedRetryMin = time.Minute
	failedRetryMax = 10 * time.Minute
	// prepareNetworkTimeout bounds the network step of prepare (plugin/policy prefetch), so a
	// hung registry cannot stall the reconciler. A timeout is a failed/download-failed, which
	// is retried with the failed backoff.
	prepareNetworkTimeout = 5 * time.Minute
)

// candidate is a complete, validated configuration that is ready to run. The reconciler builds
// it BEFORE cancelling the running configuration (prepare-then-cancel, R32). It is immutable
// once built.
type candidate struct {
	base     *baseSnapshot
	declared agentconfig.Config // the declared config the runtime was built from
	runtime  *agentConfig       // resolved, enabled-only, skipped plugins removed
	// identity changes whenever anything that affects the runtime changes, including the
	// values the digest masks or omits (api block, secrets). It never leaves the process.
	identity string
}

// applyError is why a candidate could not be prepared. Status is agentconfig.StatusRejected
// or agentconfig.StatusFailed and Reason is one of agentconfig.Reasons.
type applyError struct {
	Status string
	Reason string
	Err    error
	// runtime is the prepared runtime of a download-failed candidate: startup hands it to
	// onStartupFailure so the startup-failure evidence describes it, as on main.
	runtime *agentConfig
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

func failed(reason string, err error) *applyError {
	return &applyError{Status: agentconfig.StatusFailed, Reason: reason, Err: err}
}

// prefetcher is the part of AgentRunner the reconciler drives (a test seam).
type prefetcher interface {
	Prefetch(ctx context.Context, cfg *agentConfig) error
}

// runFunc runs one configuration until it is cancelled (daemon) or completes (one-shot).
type runFunc func(ctx context.Context, cfg *agentConfig) error

type trigger int

const (
	triggerFile trigger = iota
	triggerPoll
)

// reconciler is the single writer of the configuration state. Triggers are serialized in one
// goroutine: a trigger builds a complete candidate and only then cancels the running
// configuration; a failure tears nothing down.
type reconciler struct {
	cmd        *cobra.Command
	configPath string
	store      *agentstate.Store
	runner     prefetcher
	logger     hclog.Logger
	fileEvents chan struct{}
	runFailed  chan *candidate
	// onStartupFailure records a startup download failure of the file-only configuration
	// (plugin run state + startup-failure agent evidence, as AgentRunner.Run always did).
	onStartupFailure func(ctx context.Context, cfg *agentConfig, err error)
	// debounce coalesces bursts of config file events (editors write in several steps).
	debounce time.Duration

	now func() time.Time

	mu        sync.Mutex // guards active, pending, cancelRun
	active    *candidate
	pending   *candidate
	cancelRun context.CancelFunc

	// Everything below is owned by the reconciler goroutine (startup runs before loop).
	base *baseSnapshot

	failedBase     string
	failedRetryAt  time.Time
	failedInterval time.Duration
}

func newReconciler(cmd *cobra.Command, configPath string, store *agentstate.Store, runner prefetcher, logger hclog.Logger) *reconciler {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	rc := &reconciler{
		cmd:        cmd,
		configPath: configPath,
		store:      store,
		runner:     runner,
		logger:     logger.Named("reconciler"),
		fileEvents: make(chan struct{}, 1),
		runFailed:  make(chan *candidate, 1),
		debounce:   500 * time.Millisecond,
		now:        time.Now,
	}
	return rc
}

func (rc *reconciler) rcfg() agentconfig.RemoteConfig {
	return rc.base.declared.EffectiveRemoteConfig()
}

// setBase installs a new base and logs its warnings.
func (rc *reconciler) setBase(base *baseSnapshot) {
	rc.base = base
	rc.logWarnings(base.warnings)
}

// startup loads the file and prepares it (R32). Only an unusable local configuration is an
// error (exit 1, as before).
func (rc *reconciler) startup(ctx context.Context) (*candidate, error) {
	base, err := loadBase(rc.cmd, rc.configPath)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	rc.setBase(base)

	active, aerr := rc.prepare(ctx, base)
	if aerr != nil {
		if aerr.runtime != nil && rc.onStartupFailure != nil {
			rc.onStartupFailure(ctx, aerr.runtime, aerr.Err)
		}
		return nil, aerr
	}
	return active, nil
}

// startFailedBackoff starts (or doubles, for the same base) the retry delay of a candidate that
// failed to prepare or to run on base baseFingerprint.
func (rc *reconciler) startFailedBackoff(baseFingerprint string) {
	if rc.failedBase == baseFingerprint && rc.failedInterval > 0 {
		rc.failedInterval = min(rc.failedInterval*2, failedRetryMax)
	} else {
		rc.failedInterval = failedRetryMin
	}
	rc.failedBase = baseFingerprint
	rc.failedRetryAt = rc.now().Add(rc.failedInterval)
}

func (rc *reconciler) inFailedBackoff() bool {
	return rc.failedInterval > 0 && rc.failedBase == rc.base.fingerprint && rc.now().Before(rc.failedRetryAt)
}

// clearFailedBackoff forgets the failed backoff after a candidate prepared on the current base,
// unless it is the base in backoff: that one may still fail to RUN, and the retry delay must
// keep growing instead of restarting at failedRetryMin (no flapping every poll).
func (rc *reconciler) clearFailedBackoff() {
	if rc.failedBase == rc.base.fingerprint {
		return
	}
	rc.failedBase, rc.failedInterval = "", 0
}

// prepare builds a candidate from a base. It never touches the running configuration.
func (rc *reconciler) prepare(ctx context.Context, base *baseSnapshot) (*candidate, *applyError) {
	declared := base.declared
	runtime, err := toRuntime(declared, base.skip)
	if err != nil {
		return nil, failed(agentconfig.ReasonInvalidConfig, err)
	}
	prefetchCtx, cancelPrefetch := context.WithTimeout(ctx, prepareNetworkTimeout)
	err = rc.runner.Prefetch(prefetchCtx, runtime)
	cancelPrefetch()
	if err != nil {
		aerr := failed(agentconfig.ReasonDownloadFailed, err)
		aerr.runtime = runtime
		return nil, aerr
	}
	return &candidate{
		base:     base,
		declared: declared,
		runtime:  runtime,
		identity: candidateIdentity(declared),
	}, nil
}

// candidateIdentity hashes the declared config, including the values the digest masks or
// omits, so any change that affects the runtime is a different configuration.
func candidateIdentity(c agentconfig.Config) string {
	raw, err := agentconfig.CanonicalJSON(struct {
		Config agentconfig.Config `json:"config"`
	}{c})
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

// adopt records cand, whose identity equals old's, as the running (or pending) configuration
// WITHOUT a restart: the runtime old runs is kept, and sameAsActive holds for cand's base on
// the next trigger (no re-prepare every poll).
func (rc *reconciler) adopt(old, cand *candidate) *candidate {
	adopted := *cand
	if old.runtime != nil {
		adopted.runtime = old.runtime
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	switch {
	case rc.pending == old:
		rc.pending = &adopted
	case rc.active == old:
		rc.active = &adopted
	}
	return &adopted
}

// record returns the reconciler's current record of the candidate running c.runtime: adopt
// may have replaced it in place.
func (rc *reconciler) record(c *candidate) *candidate {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.active != nil && c != nil && rc.active.runtime == c.runtime {
		return rc.active
	}
	return c
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
	var previous, failedRun *candidate
	for {
		runCtx, cancel := context.WithCancel(context.Background())
		rc.bind(active, cancel)
		if failedRun != nil {
			// Notify only once the fallback is bound, so the reconciler's current() is the
			// fallback, never the candidate that failed.
			rc.notifyRunFailed(failedRun)
			failedRun = nil
		}
		runErr := run(runCtx, active.runtime)
		reload := runCtx.Err() != nil
		cancel()
		active = rc.record(active)
		if runErr != nil && !reload {
			if previous != nil {
				rc.logger.Error("Configuration failed to run; falling back to the previous configuration", "error", runErr)
				failedRun = active
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

// notifyRunFailed hands a failed-to-run candidate to the reconciler goroutine.
func (rc *reconciler) notifyRunFailed(c *candidate) {
	select {
	case rc.runFailed <- c:
	default:
	}
}

// pollDelay is the next poll delay: poll_interval ±10% jitter, at least MinPollInterval.
func (rc *reconciler) pollDelay() time.Duration {
	interval, err := time.ParseDuration(rc.rcfg().PollInterval)
	if err != nil {
		interval = agentconfig.DefaultPollInterval
	}
	interval = max(interval, agentconfig.MinPollInterval)
	jitter := time.Duration((rand.Float64()*0.2 - 0.1) * float64(interval))
	return max(interval+jitter, agentconfig.MinPollInterval)
}

// loop is the daemon's reconcile goroutine: config file events (debounced) and the poll
// ticker, which retries a candidate whose failed backoff expired. It returns when ctx is done.
func (rc *reconciler) loop(ctx context.Context) {
	var debounce <-chan time.Time
	poll := time.NewTimer(rc.pollDelay())
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rc.fileEvents:
			if debounce == nil {
				debounce = time.After(rc.debounce)
			}
		case <-debounce:
			debounce = nil
			rc.reconcile(ctx, triggerFile)
		case c := <-rc.runFailed:
			rc.onRunFailed(ctx, c)
		case <-poll.C:
			rc.reconcile(ctx, triggerPoll)
			poll.Reset(rc.pollDelay())
		}
	}
}

// onRunFailed records that a prepared candidate failed to run (the run loop already fell back).
func (rc *reconciler) onRunFailed(_ context.Context, c *candidate) {
	if c == nil {
		return
	}
	// Back the candidate off: otherwise every poll re-prepares the new base, cancels the
	// healthy configuration, fails and falls back again.
	baseFingerprint := rc.base.fingerprint
	if c.base != nil {
		baseFingerprint = c.base.fingerprint
	}
	rc.startFailedBackoff(baseFingerprint)
}

// reconcile handles one trigger (G3.4). All work runs in the reconciler goroutine, so two
// prepares never overlap.
func (rc *reconciler) reconcile(ctx context.Context, t trigger) {
	if t == triggerFile {
		base, err := loadBase(rc.cmd, rc.configPath)
		if err != nil {
			rc.logger.Error("Config file is invalid; keeping the running configuration", "error", err)
			return
		}
		rc.setBase(base)
	}

	active := rc.current()
	if rc.sameAsActive(active) || rc.inFailedBackoff() {
		return
	}

	cand, aerr := rc.prepare(ctx, rc.base)
	if aerr != nil {
		rc.logger.Warn("Could not apply the configuration; keeping the running configuration", "status", aerr.Status, "reason", aerr.Reason, "error", aerr.Err)
		rc.startFailedBackoff(rc.base.fingerprint)
		return
	}
	rc.clearFailedBackoff()
	if active != nil && active.identity == cand.identity {
		rc.logger.Debug("Trigger did not change the effective configuration; recording it without a restart")
		rc.adopt(active, cand)
		return
	}
	rc.logger.Info("Applying the new configuration")
	rc.swap(cand)
}

// sameAsActive reports whether the active candidate already runs this base.
func (rc *reconciler) sameAsActive(active *candidate) bool {
	return active != nil && active.base != nil &&
		bytes.Equal(active.base.raw, rc.base.raw) && active.base.fingerprint == rc.base.fingerprint
}

func (rc *reconciler) logWarnings(warnings []agentconfig.FieldError) {
	for _, w := range warnings {
		if isToleratedFileRule(w) {
			rc.logger.Warn("Ignoring a problem in the config file; the plugin is skipped", "path", w.Path, "error", w.Message)
			continue
		}
		rc.logger.Warn("Ignoring a problem in the config file; the value is kept unchanged", "path", w.Path, "error", w.Message)
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
