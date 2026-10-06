package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"runtime/debug"
	"slices"
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

// pluginLibFunc returns the agent library version the binary of a plugin source was built
// with ("" when unknown). The source has been prefetched.
type pluginLibFunc func(ctx context.Context, source string) (string, error)

// pluginReports lists the plugins of runtime with the agent library each was built with (R76),
// read from the plugin binary's build info: diagnostics for the UI. A version that cannot be
// read is reported as unknown (empty). Without a pluginLib function it reports nothing.
func (rc *reconciler) pluginReports(ctx context.Context, runtime *agentConfig) []agentconfig.PluginReport {
	if rc.pluginLib == nil || runtime == nil {
		return nil
	}
	var reports []agentconfig.PluginReport
	for _, name := range slices.Sorted(maps.Keys(runtime.Plugins)) {
		p := runtime.Plugins[name]
		version, err := rc.pluginLib(ctx, p.Source)
		if err != nil {
			version = ""
			if rc.logOnce("plugin-lib\x00" + p.Source + "\x00" + err.Error()) {
				rc.logger.Warn("Could not read the agent library version of a plugin; reporting it as unknown", "plugin", name, "source", p.Source, "error", err)
			}
		}
		reports = append(reports, agentconfig.PluginReport{Name: name, Source: p.Source, LibVersion: version})
	}
	return reports
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
		Hostname:        truncateString(hostname, 255),
		AgentVersion:    truncateString(agentVersion, 64),
		Mode:            rcfg.Mode,
		Daemon:          active.runtime.Daemon,
		Base:            marshalRaw(agentconfig.Redact(active.base.declared, opts...)),
		Effective:       marshalRaw(agentconfig.Redact(active.declared, opts...)),
		EffectiveDigest: active.digest,
		Warnings:        active.warnings,
		RemoteConfig:    &rcfg,
		Plugins:         active.plugins,
	}
	switch {
	case !isApplyMode(rcfg.Mode):
		report.Status = agentconfig.StatusNotApplicable
	case outcome != nil:
		report.Status = outcome.Status
		report.Reason = outcome.Reason
		msg := outcome.Reason
		if outcome.Err != nil {
			msg = outcome.Err.Error()
		}
		report.Error = &msg
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
// force is set, for a resend after a 413): base is dropped, which sets Truncated. It returns the body and its fingerprint.
func fitReport(report *agentconfig.Report, force bool) ([]byte, string, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return nil, "", err
	}
	steps := []func(*agentconfig.Report){dropReportBase}
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

func dropReportBase(report *agentconfig.Report) {
	report.Base = json.RawMessage(`{}`)
}
