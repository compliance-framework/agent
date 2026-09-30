package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/compliance-framework/api/sdk"
)

// reportTargetBytes is the size the agent aims for; the API limit is agentconfig.MaxReportBytes.
const reportTargetBytes = 3*(1<<20) + (1 << 19) // 3.5 MiB

// agentVersion is the agent build version reported to the API (see SetAgentVersion).
var agentVersion = "dev"

// SetAgentVersion sets the version reported in config reports. main passes the goreleaser
// ldflag value; "dev" (or empty) falls back to the module version for `go install` builds.
func SetAgentVersion(v string) {
	v = strings.TrimSpace(v)
	if v == "" || v == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		} else {
			v = "dev"
		}
	}
	agentVersion = v
}

// reportState is the reconciler's report bookkeeping.
type reportState struct {
	fingerprint string    // sha256 of the last report sent successfully
	sentAt      time.Time // when it was sent
	sendFailed  bool      // the last attempt failed; retry on the next tick
}

// maybeReport sends a config report for active when it differs from the last one sent, after a
// send error, or when the last one is older than 24h (G2.2). Mode off never reports.
func (rc *reconciler) maybeReport(ctx context.Context, active *candidate, outcome *applyError) {
	if active == nil || rc.remote == nil {
		return
	}
	rcfg := rc.rcfg()
	if rcfg.Mode == agentconfig.ModeOff {
		return
	}
	if rc.now().Before(rc.reportBackoffUntil) {
		return
	}
	report := rc.buildReport(active, outcome, rcfg)
	body, fingerprint, err := fitReport(&report, false)
	if err != nil {
		rc.logger.Error("Could not encode the config report", "error", err)
		return
	}
	if !rc.report.sendFailed && fingerprint == rc.report.fingerprint && rc.now().Sub(rc.report.sentAt) < reportResendInterval {
		return
	}
	if len(body) > agentconfig.MaxReportBytes {
		rc.logger.Warn("Config report exceeds the API limit even after truncation", "bytes", len(body))
	}

	err = rc.sendReport(ctx, report)
	var statusErr *sdk.APIStatusError
	if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusRequestEntityTooLarge {
		rc.logger.Warn("The API rejected the config report as too large; resending it truncated")
		if _, _, ferr := fitReport(&report, true); ferr == nil {
			err = rc.sendReport(ctx, report)
		}
	}
	switch {
	case err == nil:
		rc.report = reportState{fingerprint: fingerprint, sentAt: rc.now()}
		if outcome != nil && outcome.Reason == agentconfig.ReasonCacheCorrupt && rc.lastOutcome == outcome {
			rc.lastOutcome = nil // reported once
		}
	case errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusConflict:
		rc.report.sendFailed = true
		rc.reportBackoffUntil = rc.now().Add(reportConflictBackoff)
		rc.logger.Warn("The API refused the config report: the agent's instance cap is reached; pausing reports", "retry_in", reportConflictBackoff, "error", err)
	default:
		rc.report.sendFailed = true
		rc.handleRemoteError("report", err, &rc.reportBackoffUntil)
	}
}

func (rc *reconciler) sendReport(ctx context.Context, report agentconfig.Report) error {
	reportCtx, cancel := context.WithTimeout(ctx, remoteRequestTimeout)
	defer cancel()
	return rc.remote.Report(reportCtx, rc.instanceID, report)
}

// buildReport fills the wire report for the active candidate and the last outcome (G2.2).
// base and effective are the UNRESOLVED forms, redacted with the same masked pointers the
// digest uses (R24, R25, R55).
func (rc *reconciler) buildReport(active *candidate, outcome *applyError, rcfg agentconfig.RemoteConfig) agentconfig.Report {
	hostname, _ := os.Hostname()
	opts := active.base.redactOpts()
	report := agentconfig.Report{
		Hostname:          truncateString(hostname, 255),
		AgentVersion:      truncateString(agentVersion, 64),
		Mode:              rcfg.Mode,
		Daemon:            active.runtime.Daemon,
		AppliedRevision:   active.appliedRevision(),
		AttemptedRevision: rc.attempted,
		Base:              marshalRaw(agentconfig.Redact(active.base.declared, opts...)),
		Effective:         marshalRaw(agentconfig.Redact(active.declared, opts...)),
		EffectiveDigest:   active.digest,
		PolicyBundles:     append([]agentconfig.PolicyBundleReport(nil), active.bundles...),
		Warnings:          active.warnings,
		RemoteConfig:      &rcfg,
	}
	report.PolicyErrors = append(report.PolicyErrors, active.policyWarnings...)
	switch {
	case !isApplyMode(rcfg.Mode):
		report.Status = agentconfig.StatusNotApplicable
		report.AttemptedRevision = nil
	case outcome != nil:
		report.Status = outcome.Status
		report.Reason = outcome.Reason
		msg := outcome.Reason
		if outcome.Err != nil {
			msg = outcome.Err.Error()
		}
		report.Error = &msg
		report.Unsafe = outcome.Unsafe
		report.PolicyErrors = append(append([]agentconfig.PolicyError(nil), outcome.PolicyErrors...), report.PolicyErrors...)
	default:
		report.Status = agentconfig.StatusApplied
	}
	return report
}

func marshalRaw(c agentconfig.Config) json.RawMessage {
	raw, err := json.Marshal(c)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// fitReport encodes the report, shrinking it to reportTargetBytes when needed (or always when
// force is set, for a resend after a 413): first every policy bundle module in base and
// effective becomes "sha256:<hex>", then the policy bundle file lists are dropped, then base
// is dropped. Any step sets Truncated. It returns the body and its fingerprint.
func fitReport(report *agentconfig.Report, force bool) ([]byte, string, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return nil, "", err
	}
	steps := []func(*agentconfig.Report){hashReportModules, dropReportFileLists, dropReportBase}
	for _, step := range steps {
		if !force && len(body) <= reportTargetBytes {
			break
		}
		step(report)
		report.Truncated = true
		if body, err = json.Marshal(report); err != nil {
			return nil, "", err
		}
	}
	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), nil
}

func hashReportModules(report *agentconfig.Report) {
	report.Base = hashDocModules(report.Base)
	report.Effective = hashDocModules(report.Effective)
}

// hashDocModules replaces policy_bundles.*.modules.* values with "sha256:<hex>".
func hashDocModules(doc json.RawMessage) json.RawMessage {
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(string(doc)))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return doc
	}
	bundles, _ := obj["policy_bundles"].(map[string]any)
	for _, raw := range bundles {
		b, _ := raw.(map[string]any)
		modules, _ := b["modules"].(map[string]any)
		for p, src := range modules {
			if s, ok := src.(string); ok {
				sum := sha256.Sum256([]byte(s))
				modules[p] = "sha256:" + hex.EncodeToString(sum[:])
			}
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return doc
	}
	return out
}

func dropReportFileLists(report *agentconfig.Report) {
	for i := range report.PolicyBundles {
		report.PolicyBundles[i].Files = []agentconfig.PolicyFileReport{}
		if report.PolicyBundles[i].Extends != nil {
			ext := *report.PolicyBundles[i].Extends
			ext.Files = []agentconfig.PolicyFileReport{}
			report.PolicyBundles[i].Extends = &ext
		}
	}
}

func dropReportBase(report *agentconfig.Report) {
	report.Base = json.RawMessage(`{}`)
}
