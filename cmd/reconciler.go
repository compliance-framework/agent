package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/compliance-framework/agent/internal/agentstate"
	"github.com/compliance-framework/agent/internal/inlinepolicy"
	"github.com/compliance-framework/agent/internal/policyview"
	runnerpkg "github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/sdk"
	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// remoteRequestTimeout bounds one config fetch or report; the startup fetch too.
	remoteRequestTimeout = 30 * time.Second
	// remoteAuthBackoff is the retry delay after a 404 (API without the feature) or a 401/403
	// on a config route (R8, R36).
	remoteAuthBackoff = 10 * time.Minute
	// reportConflictBackoff is the report pause after a 409 (per-agent instance cap, R36).
	reportConflictBackoff = time.Hour
	// reportResendInterval resends an unchanged report in case the API pruned or lost it.
	reportResendInterval = 24 * time.Hour
	// failedRetryMin / failedRetryMax bound the retry of a failed/* revision.
	failedRetryMin = time.Minute
	failedRetryMax = 10 * time.Minute
	// prepareNetworkTimeout bounds each network step of prepare (plugin/policy prefetch, an
	// extends tree, a report inventory), so a hung registry cannot stall the reconciler. A
	// timeout is a failed/download-failed, which is retried with the failed backoff.
	prepareNetworkTimeout = 5 * time.Minute
)

// candidate is a complete, validated configuration that is ready to run. The reconciler builds
// it BEFORE cancelling the running configuration (prepare-then-cancel, R32). It is immutable
// once built.
type candidate struct {
	base     *baseSnapshot
	overlay  *agentstate.OverlayRecord // nil = file only
	declared agentconfig.Config        // merged, ${env:} NOT resolved: reported and digested
	runtime  *agentConfig              // resolved, enabled-only, skipped plugins removed, inline dirs set
	digest   string                    // agentconfig.Digest(declared, base.redactOpts()...) (R55)
	// identity changes whenever anything that affects the runtime changes, including the
	// values the digest masks or omits (api block, secrets). It never leaves the process.
	identity string
	bundles  []agentconfig.PolicyBundleReport
	// trees are the policy trees bundles describe, uploaded as artifacts for the report (R62).
	trees          []artifactTree
	warnings       []agentconfig.FieldError  // R34 file-origin warnings
	policyWarnings []agentconfig.PolicyError // G3b severity=warning
	// plugins are the runtime's plugins with their agent library versions (R76).
	plugins []agentconfig.PluginReport
}

// appliedRevision is the overlay revision the candidate applies, or nil for the file only.
func (c *candidate) appliedRevision() *int64 {
	if c == nil || c.overlay == nil {
		return nil
	}
	rev := c.overlay.Revision
	return &rev
}

// applyError is why a candidate could not be prepared. Status is agentconfig.StatusRejected
// or agentconfig.StatusFailed and Reason is one of agentconfig.Reasons.
type applyError struct {
	Status       string
	Reason       string
	Err          error
	Unsafe       []agentconfig.Change
	PolicyErrors []agentconfig.PolicyError
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

func rejected(reason string, err error) *applyError {
	return &applyError{Status: agentconfig.StatusRejected, Reason: reason, Err: err}
}

func failed(reason string, err error) *applyError {
	return &applyError{Status: agentconfig.StatusFailed, Reason: reason, Err: err}
}

// prefetcher is the part of AgentRunner the reconciler drives (a test seam).
type prefetcher interface {
	Prefetch(ctx context.Context, cfg *agentConfig) error
}

// overlayFetcher is the test seam over sdk.Client.AgentConfig.Get.
type overlayFetcher interface {
	Get(ctx context.Context, ifNoneMatch string) (*sdk.AgentConfigResult, error)
}

// configReporter is the test seam over sdk.Client.AgentConfig.Report.
type configReporter interface {
	Report(ctx context.Context, instanceID uuid.UUID, r agentconfig.Report) error
}

// artifactUploader is the test seam over the shared artifact uploader (R62).
type artifactUploader interface {
	UploadArtifact(ctx context.Context, mediaType string, content []byte) (string, error)
}

// remoteAPI bundles the remote configuration calls and the artifact upload.
type remoteAPI interface {
	overlayFetcher
	configReporter
	artifactUploader
}

// sdkRemote adapts the SDK client to remoteAPI. Artifacts go through the process-wide
// uploader, shared with the plugins' API helpers.
type sdkRemote struct {
	client    *sdk.Client
	artifacts *runnerpkg.ArtifactEndpoint
}

func (s sdkRemote) UploadArtifact(ctx context.Context, mediaType string, content []byte) (string, error) {
	return s.artifacts.Upload(ctx, mediaType, content)
}

func (s sdkRemote) Get(ctx context.Context, ifNoneMatch string) (*sdk.AgentConfigResult, error) {
	return s.client.AgentConfig.Get(ctx, ifNoneMatch)
}

func (s sdkRemote) Report(ctx context.Context, instanceID uuid.UUID, r agentconfig.Report) error {
	return s.client.AgentConfig.Report(ctx, instanceID, r)
}

// newSDKRemote builds the remote configuration client from the (locked, file-only) api block.
func newSDKRemote(c agentconfig.Config, uploader *runnerpkg.ArtifactUploader) remoteAPI {
	if c.API == nil {
		return nil
	}
	cfg := &sdk.Config{BaseURL: strings.TrimSpace(c.API.URL)}
	if c.API.HasAuth() {
		cfg.AgentAuth = &sdk.AgentAuthConfig{
			ClientID:     strings.TrimSpace(c.API.Auth.ClientID),
			ClientSecret: strings.TrimSpace(c.API.Auth.ClientSecret),
		}
	}
	client := sdk.NewClient(nil, cfg)
	return sdkRemote{client: client, artifacts: uploader.Endpoint(cfg.BaseURL, client.Artifact)}
}

// runFunc runs one configuration until it is cancelled (daemon) or completes (one-shot).
type runFunc func(ctx context.Context, cfg *agentConfig) error

type trigger int

const (
	triggerFile trigger = iota
	triggerPoll
)

// reconciler is the single writer of the configuration state. File and remote triggers are
// serialized in one goroutine: a trigger builds a complete candidate and only then cancels the
// running configuration; a failure tears nothing down.
type reconciler struct {
	cmd        *cobra.Command
	configPath string
	store      *agentstate.Store
	runner     prefetcher
	logger     hclog.Logger
	instanceID uuid.UUID
	fileEvents chan struct{}
	runFailed  chan *candidate
	// onStartupFailure records a startup download failure of the file-only configuration
	// (plugin run state + startup-failure agent evidence, as AgentRunner.Run always did).
	onStartupFailure func(ctx context.Context, cfg *agentConfig, err error)
	// debounce coalesces bursts of config file events (editors write in several steps).
	debounce time.Duration

	// newRemote builds the remote client from a base (a test seam).
	newRemote func(agentconfig.Config) remoteAPI
	// lookupEnv resolves ${env:NAME} placeholders (a test seam).
	lookupEnv func(string) (string, bool)
	// resolvePolicy returns the policy root of an OCI or local policy source (downloading it
	// into the shared cache); it serves inline bundles' extends and the report inventory.
	resolvePolicy inlinepolicy.Resolver
	// inlineLinks overrides inlineLinksDir, where plugins receive inline bundles (a test
	// seam: the default is relative to the working directory).
	inlineLinks string
	// pluginLib reads the agent library version of a prefetched plugin source (R76);
	// nil skips the plugin compatibility checks and report.
	pluginLib pluginLibFunc
	// inventoryMemo caches the report inventory of OCI policy trees ("source\x00dir"), and
	// identityMemo their modules' evidence identities.
	inventoryMemo map[string]agentconfig.PolicyBundleReport
	identityMemo  map[string][]inlinepolicy.ModuleIdentity
	// artifacts is the process-wide artifact uploader (shared with the plugins' API helpers).
	artifacts *runnerpkg.ArtifactUploader
	// artifactMemo maps a policy tree digest to the digest of its uploaded artifact ("" when
	// the API refused it for good). Owned by the reconciler goroutine.
	artifactMemo map[string]string
	now          func() time.Time

	mu      sync.Mutex // guards active, pending, starting, fallback, cancelRun
	active  *candidate
	pending *candidate
	// starting is the candidate the run loop took from pending and is about to bind;
	// fallback is the one it falls back to if the running one fails. GC keeps their trees.
	starting  *candidate
	fallback  *candidate
	cancelRun context.CancelFunc
	// inlineMu serializes activating inline trees (run loop) with GC (reconciler goroutine).
	inlineMu sync.Mutex

	// Everything below is owned by the reconciler goroutine (startup runs before loop).
	base        *baseSnapshot
	remote      remoteAPI
	remoteKey   string
	cache       *agentstate.Cache
	lastOutcome *applyError
	attempted   *int64
	warnedMode  bool

	fetchBackoffUntil  time.Time
	reportBackoffUntil time.Time
	loggedOnce         map[string]bool

	failedKey      string // overlayKey of the target in failed backoff
	failedBase     string
	failedRetryAt  time.Time
	failedInterval time.Duration

	report reportState
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
		lookupEnv:  os.LookupEnv,
		now:        time.Now,
		loggedOnce: map[string]bool{},

		inventoryMemo: map[string]agentconfig.PolicyBundleReport{},
		identityMemo:  map[string][]inlinepolicy.ModuleIdentity{},
		artifacts:     runnerpkg.NewArtifactUploader(),
		artifactMemo:  map[string]string{},
	}
	rc.newRemote = func(c agentconfig.Config) remoteAPI { return newSDKRemote(c, rc.artifacts) }
	return rc
}

func (rc *reconciler) rcfg() agentconfig.RemoteConfig {
	return rc.base.declared.EffectiveRemoteConfig()
}

func isApplyMode(mode string) bool {
	return mode == agentconfig.ModeApplySafe || mode == agentconfig.ModeApplyAll
}

// setBase installs a new base: warnings are logged, the remote client is rebuilt when the api
// block changed, and the cache is (re)bound to the base's identity.
func (rc *reconciler) setBase(base *baseSnapshot) {
	old := rc.base
	rc.base = base
	rc.logWarnings(base.warnings)
	if !rc.warnedMode && base.declared.RemoteConfig != nil {
		mode := base.declared.RemoteConfig.Mode
		if mode != "" && mode != agentconfig.ModeOff && !base.declared.API.HasAuth() {
			rc.warnedMode = true
			rc.logger.Warn("remote_config.mode needs api.auth credentials; remote configuration is off", "mode", mode)
		}
	}

	key := remoteKey(base.declared)
	if rc.remote == nil || key != rc.remoteKey {
		rc.remote = nil
		if base.declared.API.HasAuth() {
			rc.remote = rc.newRemote(base.declared)
		}
		rc.remoteKey = key
		rc.fetchBackoffUntil, rc.reportBackoffUntil = time.Time{}, time.Time{}
		// Artifacts uploaded to the previous API are not in this one.
		rc.artifactMemo = map[string]string{}
	}

	id := cacheIdentity(base.declared)
	if rc.cache == nil || rc.cache.Identity != id {
		cache, err := rc.store.LoadCache(id)
		rc.cache = cache
		if errors.Is(err, agentstate.ErrCacheCorrupt) {
			rc.logger.Error("Remote config cache is corrupt; continuing without it", "path", rc.store.CachePath(), "error", err)
			rc.lastOutcome = failed(agentconfig.ReasonCacheCorrupt, err)
		}
	}
	if old != nil && old.fingerprint != base.fingerprint && rc.cache.Rejected != nil {
		// A base change re-classifies a remembered rejection.
		rc.cache.Rejected = nil
		rc.saveCache()
	}
}

func remoteKey(c agentconfig.Config) string {
	if c.API == nil {
		return ""
	}
	raw, _ := json.Marshal(c.API)
	return string(raw)
}

func cacheIdentity(c agentconfig.Config) agentstate.Identity {
	id := agentstate.Identity{}
	if c.API != nil {
		id.APIURL = strings.TrimSpace(c.API.URL)
		if c.API.Auth != nil {
			id.ClientID = strings.TrimSpace(c.API.Auth.ClientID)
		}
	}
	return id
}

func (rc *reconciler) saveCache() {
	if rc.cache == nil {
		return
	}
	if err := rc.store.SaveCache(rc.cache); err != nil && rc.logOnce("cache-save") {
		rc.logger.Warn("Could not persist the remote config cache", "path", rc.store.CachePath(), "error", err)
	}
}

// logOnce reports whether key has not been logged yet, and marks it.
func (rc *reconciler) logOnce(key string) bool {
	if rc.loggedOnce[key] {
		return false
	}
	rc.loggedOnce[key] = true
	return true
}

// startup runs the startup ladder (R32): load the file, fetch (apply modes, bounded), then the
// first candidate that prepares wins among base+fetched, base+applied and base only. Only an
// unusable local configuration is an error (exit 1, as before).
func (rc *reconciler) startup(ctx context.Context) (*candidate, error) {
	base, err := loadBase(rc.cmd, rc.configPath)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	rc.setBase(base)
	rcfg := rc.rcfg()
	if isApplyMode(rcfg.Mode) {
		rc.fetch(ctx)
	}

	var active *candidate
	var outcome *applyError
	for _, target := range rc.ladder(rcfg.Mode) {
		cand, aerr := rc.prepare(ctx, base, target)
		if target != nil && target == rc.cache.Fetched {
			rev := target.Revision
			rc.attempted = &rev
		}
		if aerr != nil {
			if target == nil {
				if aerr.runtime != nil && rc.onStartupFailure != nil {
					rc.onStartupFailure(ctx, aerr.runtime, aerr.Err)
				}
				return nil, aerr
			}
			rc.logger.Warn("Could not apply the remote configuration at startup", "revision", target.Revision, "status", aerr.Status, "reason", aerr.Reason, "error", aerr.Err)
			rc.recordFailure(target, aerr)
			if outcome == nil {
				outcome = aerr
			}
			continue
		}
		active = cand
		if target != nil {
			rc.cache.Applied = target
			rc.saveCache()
		}
		break
	}
	if outcome != nil {
		rc.lastOutcome = outcome
	}
	rc.maybeReport(ctx, active, rc.lastOutcome)
	rc.afterStartup(active)
	return active, nil
}

// ladder lists the startup targets in order; nil is the file only.
func (rc *reconciler) ladder(mode string) []*agentstate.OverlayRecord {
	if !isApplyMode(mode) {
		return []*agentstate.OverlayRecord{nil}
	}
	var out []*agentstate.OverlayRecord
	if f := rc.cache.Fetched; f != nil && !rc.rememberedRejected(f) {
		out = append(out, f)
	}
	if a := rc.cache.Applied; a != nil && (len(out) == 0 || !sameOverlay(a, out[0])) {
		out = append(out, a)
	}
	return append(out, nil)
}

func sameOverlay(a, b *agentstate.OverlayRecord) bool {
	switch {
	case a == nil || b == nil:
		return a == b
	case a.ETag != "" || b.ETag != "":
		return a.ETag == b.ETag && a.Revision == b.Revision
	default:
		return a.Revision == b.Revision && bytes.Equal(a.Overlay, b.Overlay)
	}
}

// overlayKey identifies an overlay for the rejected memory and the failed backoff: the raw
// ETag, or revision + sha256(overlay) when a response carried no ETag (a stripping proxy), so
// one rejection never blocks every later revision. nil (the file only) has its own key.
func overlayKey(rec *agentstate.OverlayRecord) string {
	switch {
	case rec == nil:
		return "file-only"
	case rec.ETag != "":
		return "etag:" + rec.ETag
	default:
		return fmt.Sprintf("rev:%d:%s", rec.Revision, overlayDigest(rec.Overlay))
	}
}

func overlayDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (rc *reconciler) rememberedRejected(rec *agentstate.OverlayRecord) bool {
	r := rc.cache.Rejected
	if r == nil || rec == nil || r.BaseFingerprint != rc.base.fingerprint {
		return false
	}
	if r.ETag != "" || rec.ETag != "" {
		return r.ETag == rec.ETag
	}
	return r.Revision == rec.Revision && r.OverlaySHA256 == overlayDigest(rec.Overlay)
}

// recordFailure remembers a rejected revision for (overlay key, base), or starts the failed
// backoff. A file-only candidate that fails to prepare is backed off too.
func (rc *reconciler) recordFailure(target *agentstate.OverlayRecord, aerr *applyError) {
	if target == nil {
		rc.startFailedBackoff(nil, rc.base.fingerprint)
		return
	}
	if aerr.Status == agentconfig.StatusRejected {
		msg := ""
		if aerr.Err != nil {
			msg = aerr.Err.Error()
		}
		rc.cache.Rejected = &agentstate.RejectedRecord{
			Revision:        target.Revision,
			ETag:            target.ETag,
			OverlaySHA256:   overlayDigest(target.Overlay),
			BaseFingerprint: rc.base.fingerprint,
			Status:          aerr.Status,
			Reason:          aerr.Reason,
			Error:           msg,
		}
		rc.saveCache()
		return
	}
	rc.startFailedBackoff(target, rc.base.fingerprint)
}

// startFailedBackoff starts (or doubles, for the same target and base) the retry delay of a
// target (nil = the file only) that failed to prepare or to run on base baseFingerprint.
func (rc *reconciler) startFailedBackoff(target *agentstate.OverlayRecord, baseFingerprint string) {
	key := overlayKey(target)
	if rc.failedKey == key && rc.failedBase == baseFingerprint && rc.failedInterval > 0 {
		rc.failedInterval = min(rc.failedInterval*2, failedRetryMax)
	} else {
		rc.failedInterval = failedRetryMin
	}
	rc.failedKey, rc.failedBase = key, baseFingerprint
	rc.failedRetryAt = rc.now().Add(rc.failedInterval)
}

func (rc *reconciler) inFailedBackoff(target *agentstate.OverlayRecord) bool {
	return rc.failedInterval > 0 && rc.failedKey == overlayKey(target) &&
		rc.failedBase == rc.base.fingerprint && rc.now().Before(rc.failedRetryAt)
}

// clearFailedBackoff forgets the failed backoff after target prepared on the current base,
// unless it is the target in backoff: that one may still fail to RUN, and the retry delay
// must keep growing instead of restarting at failedRetryMin (no flapping every poll).
func (rc *reconciler) clearFailedBackoff(target *agentstate.OverlayRecord) {
	if rc.failedKey == overlayKey(target) && rc.failedBase == rc.base.fingerprint {
		return
	}
	rc.failedKey, rc.failedBase, rc.failedInterval = "", "", 0
}

// prepare builds a candidate from a base and an optional overlay (G3.3). Cheap checks run
// first and nothing touches the network before the Classify gate passes. It never touches the
// running configuration.
func (rc *reconciler) prepare(ctx context.Context, base *baseSnapshot, ov *agentstate.OverlayRecord) (*candidate, *applyError) {
	rcfg := base.declared.EffectiveRemoteConfig()
	if !isApplyMode(rcfg.Mode) {
		ov = nil // report/off: the file only
	}

	declared := base.declared
	var touched []string
	if ov != nil {
		// Strict decode of the overlay: the only strict decode in the agent (R27, R51).
		if err := agentconfig.ValidateOverlay(ov.Overlay); err != nil {
			return nil, overlayValidationError(err)
		}
		changes, err := agentconfig.Classify(base.declared, ov.Overlay, rcfg)
		if err != nil {
			return nil, rejected(agentconfig.ReasonInvalidConfig, err)
		}
		if ok, why := agentconfig.WillApply(rcfg, changes); !ok {
			aerr := rejected(why, fmt.Errorf("revision %d %s", ov.Revision, strings.ReplaceAll(why, "-", " ")))
			for _, c := range changes {
				if c.Safety != agentconfig.Safe {
					aerr.Unsafe = append(aerr.Unsafe, c)
				}
			}
			return nil, aerr
		}
		merged, err := agentconfig.Merge(base.declared, ov.Overlay)
		if err != nil {
			return nil, rejected(agentconfig.ReasonInvalidConfig, err)
		}
		touched, err = overlayTouched(base.declared, merged)
		if err != nil {
			return nil, failed(agentconfig.ReasonInternal, err)
		}
		declared = merged
	}

	part := partitionByOrigin(declared.Validate(), touched)
	if len(part.overlay) > 0 || len(part.fatal) > 0 {
		errs := agentconfig.ValidationErrors(append(append([]agentconfig.FieldError{}, part.overlay...), part.fatal...))
		if ov == nil {
			return nil, failed(agentconfig.ReasonInvalidConfig, fmt.Errorf("config file: %w", errs))
		}
		return nil, rejected(agentconfig.ReasonInvalidConfig, errs)
	}

	resolved, envWarnings, err := resolveEnv(declared, base.declared, rc.lookupEnv)
	switch {
	case errors.Is(err, agentconfig.ErrEnvForbidden):
		return nil, rejected(agentconfig.ReasonForbiddenChanges, err)
	case errors.Is(err, agentconfig.ErrEnvMissing):
		return nil, failed(agentconfig.ReasonEnvMissing, err)
	case err != nil:
		return nil, failed(agentconfig.ReasonInternal, err)
	}
	for _, w := range envWarnings {
		if rc.logOnce("env-missing\x00" + w.Path + "\x00" + w.Message) {
			rc.logWarnings([]agentconfig.FieldError{w})
		}
	}

	origin := newPolicyOrigin(base.declared, touched)
	inline, aerr := rc.prepareInline(ctx, resolved, part.skip, origin)
	if aerr != nil {
		return nil, aerr
	}

	runtime, err := toRuntime(resolved, inline.dirs, part.skip)
	if err != nil {
		return nil, failed(agentconfig.ReasonInvalidConfig, err)
	}
	runtime.inlineTrees = inline.trees
	runtime.inlineDigests = inline.digests
	runtime.pluginViews = inline.views
	prefetchCtx, cancelPrefetch := context.WithTimeout(ctx, prepareNetworkTimeout)
	err = rc.runner.Prefetch(prefetchCtx, runtime)
	cancelPrefetch()
	if err != nil {
		aerr := failed(agentconfig.ReasonDownloadFailed, err)
		aerr.runtime = runtime
		return nil, aerr
	}
	compat, plugins := rc.pluginCompatibility(ctx, runtime, inline.materialized, origin)
	if agentconfig.HasPolicyErrors(compat) {
		return nil, policyRejection(append(compat, inline.warnings...))
	}
	if len(compat) > 0 {
		inline.warnings = dedupePolicyErrors(append(inline.warnings, compat...))
		agentconfig.SortPolicyErrors(inline.warnings)
	}
	if rcfg.Mode != agentconfig.ModeOff {
		reports, trees := rc.sourceReports(ctx, runtime)
		inline.reports = append(inline.reports, reports...)
		inline.artifacts = append(inline.artifacts, trees...)
	}

	// The digest is over the UNRESOLVED form with the same masking as the reported effective
	// config (R55): it never changes when a secret rotates.
	digest := agentconfig.Digest(declared, base.redactOpts()...)
	meta := syncMeta{Digest: digest, Mode: rcfg.Mode}
	if ov != nil {
		meta.AppliedRevision = ov.Revision
	}
	runtime.setSync(meta)
	return &candidate{
		base:           base,
		overlay:        ov,
		declared:       declared,
		runtime:        runtime,
		digest:         digest,
		identity:       candidateIdentity(declared, inline.trees),
		bundles:        inline.reports,
		trees:          inline.artifacts,
		warnings:       append(append([]agentconfig.FieldError{}, part.warnings...), envWarnings...),
		policyWarnings: inline.warnings,
		plugins:        plugins,
	}, nil
}

// inlineResult is what the inline bundle step contributes to a candidate (G3b).
type inlineResult struct {
	dirs      map[string]string // "inline:<name>" -> the stable path plugins receive
	trees     map[string]string // "inline:<name>" -> the materialized tree
	digests   map[string]string // "inline:<name>" -> the materialized tree's digest
	reports   []agentconfig.PolicyBundleReport
	artifacts []artifactTree
	warnings  []agentconfig.PolicyError
	// materialized are the bundles the enabled plugins use, by name.
	materialized map[string]*inlinepolicy.Materialized
	// views are the working directories of the plugins that receive a shadowed bundle.
	views map[string]*policyview.View
}

// overlayTouched returns the pointers an overlay changed, computed on the unresolved forms so
// env resolution never counts as an overlay change (R34).
func overlayTouched(base, merged agentconfig.Config) ([]string, error) {
	a, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	diff, err := agentconfig.DiffJSON(a, b)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(diff))
	for _, d := range diff {
		out = append(out, d.Path)
	}
	return out, nil
}

// overlayValidationError maps ValidateOverlay's FieldError codes to a report reason (R43).
// With several errors the first in precedence order wins: forbidden, unknown-field,
// invalid-type, invalid-config. All errors are kept in the message.
func overlayValidationError(err error) *applyError {
	var errs agentconfig.ValidationErrors
	if !errors.As(err, &errs) {
		return rejected(agentconfig.ReasonInvalidConfig, err)
	}
	rank := map[string]int{
		agentconfig.ReasonForbiddenChanges: 0,
		agentconfig.ReasonUnknownField:     1,
		agentconfig.ReasonInvalidType:      2,
		agentconfig.ReasonInvalidConfig:    3,
	}
	reason := agentconfig.ReasonInvalidConfig
	for _, e := range errs {
		r := agentconfig.ReasonInvalidConfig
		switch e.Code {
		case agentconfig.FieldCodeLockedKey, agentconfig.FieldCodeForbiddenEnv:
			r = agentconfig.ReasonForbiddenChanges
		case agentconfig.FieldCodeUnknownField:
			r = agentconfig.ReasonUnknownField
		case agentconfig.FieldCodeInvalidType:
			r = agentconfig.ReasonInvalidType
		}
		if rank[r] < rank[reason] {
			reason = r
		}
	}
	return rejected(reason, errs)
}

// candidateIdentity hashes the declared config and the materialized inline trees (not the
// stable paths, which never change), so a different tree is a different configuration.
func candidateIdentity(c agentconfig.Config, inlineDirs map[string]string) string {
	raw, err := agentconfig.CanonicalJSON(struct {
		Config     agentconfig.Config `json:"config"`
		InlineDirs map[string]string  `json:"inline_dirs,omitempty"`
	}{c, inlineDirs})
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
	rc.starting = nil
	rc.cancelRun = cancel
	if rc.pending != nil {
		cancel()
	}
}

// adopt records cand, whose identity equals old's, as the running (or pending) configuration
// WITHOUT a restart: the runtime old runs is kept and only its sync metadata changes, so the
// heartbeat, evidence and report show cand's applied revision, and sameAsActive holds for
// cand's base and overlay on the next trigger (no re-prepare every poll).
func (rc *reconciler) adopt(old, cand *candidate) *candidate {
	adopted := *cand
	if old.runtime != nil {
		adopted.runtime = old.runtime
		old.runtime.setSync(cand.runtime.syncInfo())
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

// running returns the candidate the run loop has bound (it may still be draining after a swap).
func (rc *reconciler) running() *candidate {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.active
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
	if next != nil {
		rc.starting = next
	}
	return next
}

// start activates c's inline bundles (activateInline), then records c as the running
// candidate and fallback as the one to fall back to. The run loop calls it only once the
// previous configuration's run returned (R67). starting and fallback are set first, so GC
// keeps the trees of both throughout.
func (rc *reconciler) start(c, fallback *candidate, cancel context.CancelFunc) error {
	rc.mu.Lock()
	rc.starting, rc.fallback = c, fallback
	rc.mu.Unlock()
	err := rc.activateInline(c)
	rc.bind(c, cancel)
	return err
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
		runErr := rc.start(active, previous, cancel)
		if failedRun != nil {
			// Notify only once the fallback is bound, so the reconciler's current() is the
			// fallback, never the candidate that failed.
			rc.notifyRunFailed(failedRun)
			failedRun = nil
		}
		if runErr != nil {
			rc.logger.Error("Could not activate the inline policy bundles", "error", runErr)
		} else {
			runErr = run(runCtx, active.runtime)
		}
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
// ticker. The poller lives here, not in the heartbeat cron, because it triggers reloads. It
// returns when ctx is done.
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
func (rc *reconciler) onRunFailed(ctx context.Context, c *candidate) {
	aerr := failed(agentconfig.ReasonInternal, errors.New("the configuration failed to start; running the previous configuration"))
	if c != nil {
		// File-only candidates are backed off too: otherwise every poll re-prepares the new
		// base, cancels the healthy configuration, fails and falls back again.
		baseFingerprint := rc.base.fingerprint
		if c.base != nil {
			baseFingerprint = c.base.fingerprint
		}
		rc.startFailedBackoff(c.overlay, baseFingerprint)
	}
	if c != nil && c.overlay != nil {
		if sameOverlay(rc.cache.Applied, c.overlay) {
			rc.cache.Applied = nil
			if prev := rc.current(); prev != nil && prev.overlay != nil {
				rc.cache.Applied = prev.overlay
			}
			rc.saveCache()
		}
	}
	rc.lastOutcome = aerr
	rc.maybeReport(ctx, rc.current(), aerr)
}

// reconcile handles one trigger (G3.4). All work runs in the reconciler goroutine, so two
// prepares never overlap.
func (rc *reconciler) reconcile(ctx context.Context, t trigger) {
	if t == triggerFile {
		base, err := loadBase(rc.cmd, rc.configPath)
		if err != nil {
			rc.logger.Error("Config file is invalid; keeping the running configuration", "error", err)
			aerr := failed(agentconfig.ReasonInvalidConfig, fmt.Errorf("config file: %w", err))
			rc.lastOutcome = aerr
			rc.maybeReport(ctx, rc.current(), aerr)
			return
		}
		rc.setBase(base)
	}
	rcfg := rc.rcfg()
	if isApplyMode(rcfg.Mode) && t == triggerPoll {
		rc.fetch(ctx)
	}

	target := rc.targetOverlay(rcfg.Mode)
	if isApplyMode(rcfg.Mode) && target != nil && target == rc.cache.Fetched {
		rev := target.Revision
		rc.attempted = &rev
	}
	active := rc.current()
	if rc.sameAsActive(active, target) {
		rc.maybeReport(ctx, active, rc.lastOutcome)
		return
	}
	if target != nil && rc.rememberedRejected(target) {
		// The only overlay left (the applied one) was rejected for this base, e.g. after a
		// conflicting file edit: keep the last-known-good configuration instead of
		// re-preparing (and re-running inline policy checks) on every poll (§5.4, G3.4).
		rc.maybeReport(ctx, active, rc.lastOutcome)
		return
	}
	if rc.inFailedBackoff(target) {
		rc.maybeReport(ctx, active, rc.lastOutcome)
		return
	}

	cand, aerr := rc.prepare(ctx, rc.base, target)
	if aerr != nil {
		rc.logger.Warn("Could not apply the configuration; keeping the running configuration", "status", aerr.Status, "reason", aerr.Reason, "error", aerr.Err)
		rc.recordFailure(target, aerr)
		rc.lastOutcome = aerr
		rc.maybeReport(ctx, active, aerr)
		return
	}
	rc.clearFailedBackoff(target)
	if isApplyMode(rcfg.Mode) {
		rc.cache.Applied = target
		rc.saveCache()
	}
	rc.lastOutcome = nil
	if active != nil && active.identity == cand.identity {
		rc.logger.Debug("Trigger did not change the effective configuration; recording it without a restart", "revision", revisionForLog(target))
		rc.maybeReport(ctx, rc.adopt(active, cand), nil)
		return
	}
	rc.logger.Info("Applying the new configuration", "revision", revisionForLog(target))
	rc.swap(cand)
	rc.gcInline(rc.running(), active, cand)
	rc.maybeReport(ctx, cand, nil)
}

func revisionForLog(ov *agentstate.OverlayRecord) any {
	if ov == nil {
		return "file-only"
	}
	return ov.Revision
}

// targetOverlay is the overlay the agent should run: none in report/off; otherwise the newest
// fetched one unless it was rejected for this base, else the applied one.
func (rc *reconciler) targetOverlay(mode string) *agentstate.OverlayRecord {
	if !isApplyMode(mode) || rc.cache == nil {
		return nil
	}
	if f := rc.cache.Fetched; f != nil && !rc.rememberedRejected(f) {
		return f
	}
	return rc.cache.Applied
}

// sameAsActive reports whether the active candidate already runs this base and target.
func (rc *reconciler) sameAsActive(active *candidate, target *agentstate.OverlayRecord) bool {
	return active != nil && active.base != nil &&
		bytes.Equal(active.base.raw, rc.base.raw) && active.base.fingerprint == rc.base.fingerprint &&
		sameOverlay(active.overlay, target)
}

// fetch polls the API for the overlay (R8), honoring the error backoffs. The cached overlay
// keeps applying on any error.
func (rc *reconciler) fetch(ctx context.Context) {
	if rc.remote == nil || rc.now().Before(rc.fetchBackoffUntil) {
		return
	}
	fetchCtx, cancel := context.WithTimeout(ctx, remoteRequestTimeout)
	defer cancel()
	res, err := rc.remote.Get(fetchCtx, rc.cache.IfNoneMatch())
	if err != nil {
		rc.handleRemoteError("fetch", err, &rc.fetchBackoffUntil)
		return
	}
	switch {
	case res.NotModified:
	case res.Document != nil:
		rc.cache.Fetched = &agentstate.OverlayRecord{
			Revision:  res.Document.Revision,
			ETag:      res.ETag,
			Overlay:   append(json.RawMessage(nil), res.Document.Overlay...),
			FetchedAt: rc.now().UTC(),
		}
		rc.saveCache()
	}
}

// handleRemoteError applies the R8/R36 error table to a config route error.
func (rc *reconciler) handleRemoteError(op string, err error, backoff *time.Time) {
	var statusErr *sdk.APIStatusError
	switch {
	case errors.Is(err, sdk.ErrRemoteConfigUnsupported):
		if rc.logOnce(op + ":unsupported") {
			rc.logger.Info("The API does not support remote agent configuration; running on the cached overlay or the file", "op", op, "retry_in", remoteAuthBackoff)
		}
		*backoff = rc.now().Add(remoteAuthBackoff)
	case errors.Is(err, sdk.ErrAgentAuthRequired):
		rc.logger.Error("Remote configuration requires api.auth credentials", "op", op)
		*backoff = rc.now().Add(remoteAuthBackoff)
	case errors.As(err, &statusErr) && (statusErr.StatusCode == 401 || statusErr.StatusCode == 403):
		if rc.logOnce(fmt.Sprintf("%s:%d", op, statusErr.StatusCode)) {
			msg := "The API rejected the agent's credentials for remote configuration"
			if statusErr.StatusCode == 403 {
				msg = "The agent's service account lacks the agent:sync permission for remote configuration"
			}
			rc.logger.Error(msg, "op", op, "status", statusErr.StatusCode, "retry_in", remoteAuthBackoff)
		}
		*backoff = rc.now().Add(remoteAuthBackoff)
	default:
		rc.logger.Warn("Remote configuration request failed; retrying on the next poll", "op", op, "error", err)
	}
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
