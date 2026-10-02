package runner

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/hashicorp/go-hclog"
)

type apiHelper struct {
	logger      hclog.Logger
	client      *sdk.Client
	agentLabels map[string]string
	pluginName  string
	artifacts   *ArtifactEndpoint
	// policyPaths are the policy bundle paths the plugin was given (cleaned).
	policyPaths map[string]struct{}
	// evidenceProps are appended to every evidence the plugin creates.
	evidenceProps []types.Property

	uploader *ArtifactUploader
	apiURL   string

	// pluginSource and policySources are where the plugin and its policy bundles came from,
	// recorded on evidence as _plugin_source / _plugin_digest and _policy_source /
	// _policy_digest.
	pluginSource  Source
	policySources map[string]Source
}

// Source is where a plugin or policy bundle came from.
type Source struct {
	// Reference is the source configured for it: an OCI reference or a local path.
	Reference string
	// Digest is the registry digest the OCI reference resolved to when the agent downloaded
	// it, or for a local plugin binary its SHA-256. Empty when not known.
	Digest string
}

// Evidence props recording where the plugin and policy bundle came from. The agent owns
// them; any a plugin sets are replaced.
const (
	PropPluginSource = "_plugin_source"
	PropPluginDigest = "_plugin_digest"
	PropPolicySource = "_policy_source"
	PropPolicyDigest = "_policy_digest"
)

// LabelPolicyPath is the evidence label in which plugins record the policy path they were
// given (policy-manager's _policy_path).
const LabelPolicyPath = "_policy_path"

func isSourceProp(name string) bool {
	switch name {
	case PropPluginSource, PropPluginDigest, PropPolicySource, PropPolicyDigest:
		return true
	}
	return false
}

// WithSources sets where the plugin came from, and where each policy bundle came from, keyed
// by the local path the agent gave the plugin.
func WithSources(plugin Source, policies map[string]Source) ApiHelperOption {
	return func(h *apiHelper) {
		h.pluginSource = plugin
		for path, source := range policies {
			h.policySources[filepath.Clean(path)] = source
		}
	}
}

type ApiHelperOption func(*apiHelper)

// WithPolicyPaths sets the policy bundle paths the plugin was given. The agent uploads only
// these bundles as artifacts, so a plugin cannot make the agent read anything else.
func WithPolicyPaths(paths []string) ApiHelperOption {
	return func(h *apiHelper) {
		for _, path := range paths {
			h.policyPaths[filepath.Clean(path)] = struct{}{}
		}
	}
}

// WithArtifactUploader shares the process-wide uploader (R62), so what the reconciler or
// another plugin run already uploaded to the API at apiURL is not uploaded again. Without it
// the helper uses an uploader of its own.
func WithArtifactUploader(u *ArtifactUploader, apiURL string) ApiHelperOption {
	return func(h *apiHelper) {
		if u != nil {
			h.uploader, h.apiURL = u, apiURL
		}
	}
}

// WithEvidenceProps appends props to every evidence the plugin sends, unless the evidence
// already carries a prop with the same (ns, name). The agent uses it to stamp the applied
// remote configuration revision (R38).
func WithEvidenceProps(props ...types.Property) ApiHelperOption {
	return func(h *apiHelper) {
		h.evidenceProps = append(h.evidenceProps, props...)
	}
}

func NewApiHelper(logger hclog.Logger, client *sdk.Client, agentLabels map[string]string, pluginName string, opts ...ApiHelperOption) *apiHelper {
	logger = logger.Named("api-helper")
	h := &apiHelper{
		logger:      logger,
		client:      client,
		agentLabels: agentLabels,
		pluginName:  pluginName,
		policyPaths: map[string]struct{}{},

		policySources: map[string]Source{},
	}
	for _, opt := range opts {
		opt(h)
	}
	if h.uploader == nil {
		h.uploader = NewArtifactUploader()
	}
	var artifacts ArtifactClient
	if client != nil {
		artifacts = client.Artifact
	}
	h.artifacts = h.uploader.Endpoint(h.apiURL, artifacts)
	return h
}

// CreateEvidence sends a batch of evidence to the API, one evidence at a time.
func (h *apiHelper) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	sender := h.NewEvidenceSender(ctx)
	for _, e := range evidence {
		sender.Send(e)
	}
	return sender.Close()
}

// NewEvidenceSender returns a sender that handles each evidence as it arrives: for an
// evaluation not seen before it stores the artifacts, then it sends the evidence with their
// digests. Only the digests are kept, never the evaluation's data. If an evaluation's
// artifacts cannot be stored (for example an input over the API's size limit, or still
// failing after retries), or the API does not support artifacts, its evidence is sent as
// before, without digests: it cannot be played back, but it is never lost.
func (h *apiHelper) NewEvidenceSender(ctx context.Context) EvidenceSender {
	return &apiEvidenceSender{h: h, ctx: ctx, evaluations: map[string]evaluationOutcome{}}
}

type evaluationOutcome struct {
	// refs are the stored artifacts' digests, or nil if the evidence goes without them.
	refs *types.PolicyArtifacts
	// policyPath is the evaluation's policy bundle path, kept so evidence that refers to an
	// earlier evaluation in a stream still records its policy source.
	policyPath string
}

type apiEvidenceSender struct {
	h           *apiHelper
	ctx         context.Context
	evaluations map[string]evaluationOutcome

	notReplayable int
	sendErr       error
	unsupported   bool
}

func (s *apiEvidenceSender) Send(e *proto.Evidence) {
	var outcome evaluationOutcome
	if evaluation := e.GetPolicyEvaluation(); evaluation != nil {
		outcome = s.outcome(evaluation)
		if outcome.refs == nil {
			s.notReplayable++
		}
	}
	if err := s.h.client.Evidence.Create(s.ctx, s.h.toSdk(e, outcome)); err != nil {
		s.sendErr = errors.Join(s.sendErr, err)
	}
}

func (s *apiEvidenceSender) outcome(evaluation *proto.PolicyEvaluation) evaluationOutcome {
	key := evaluationKey(evaluation)
	if outcome, seen := s.evaluations[key]; seen {
		return outcome
	}

	var outcome evaluationOutcome
	outcome.policyPath = evaluation.GetPolicyPath()
	if isReference(evaluation) {
		s.h.logger.Warn("Sending evidence without policy artifacts; it cannot be played back",
			"error", unknownEvaluation(evaluation.GetId()))
	} else {
		refs, err := s.h.storeEvaluation(s.ctx, evaluation)
		switch {
		case errors.Is(err, ErrArtifactsUnsupported):
			if !s.unsupported {
				s.unsupported = true
				s.h.logger.Warn("The API does not support policy artifacts; evidence is sent without them and cannot be played back. Upgrade the API.")
			}
		case err != nil:
			s.h.logger.Warn("Could not store policy artifacts; sending the evaluation's evidence without them, so it cannot be played back",
				"policy_path", evaluation.GetPolicyPath(), "error", err)
		default:
			outcome.refs = refs
		}
	}
	s.evaluations[key] = outcome
	return outcome
}

func (s *apiEvidenceSender) Close() error {
	if s.notReplayable > 0 && !s.unsupported {
		s.h.logger.Warn("Sent evidence without policy artifacts", "evidence_not_replayable", s.notReplayable)
	}
	return s.sendErr
}

// toSdk converts evidence for the API, merging agent, config and finding labels, and
// referring to its evaluation's stored artifacts (outcome is the zero value for evidence
// without an evaluation). The evaluation's raw data is not included.
func (h *apiHelper) toSdk(e *proto.Evidence, outcome evaluationOutcome) types.Evidence {
	evid := EvidenceProtoToSdk(e)
	evid.PolicyArtifacts = outcome.refs
	// The agent owns the source props; any a plugin set are replaced.
	props := evid.Props[:0]
	for _, prop := range evid.Props {
		if !isSourceProp(prop.Name) {
			props = append(props, prop)
		}
	}
	evid.Props = appendSource(props, h.pluginSource, PropPluginSource, PropPluginDigest)
	if outcome.policyPath == "" {
		// Plugins built on an agent library without policy evaluations still label their
		// evidence with the policy path they were given.
		if p := evid.Labels[LabelPolicyPath]; p != "" {
			if _, known := h.policySources[filepath.Clean(p)]; known {
				outcome.policyPath = p
			}
		}
	}
	if outcome.policyPath != "" {
		evid.Props = appendSource(evid.Props, h.policySources[filepath.Clean(outcome.policyPath)], PropPolicySource, PropPolicyDigest)
	}
	labels := make(map[string]string)
	for k, v := range h.agentLabels {
		labels[k] = v
	}
	for k, v := range evid.Labels {
		labels[k] = v
	}
	evid.Labels = labels
	evid.Props = mergeProps(evid.Props, h.evidenceProps)
	return *evid
}

// mergeProps appends each extra prop unless one with the same (ns, name) already exists.
func mergeProps(props []types.Property, extra []types.Property) []types.Property {
	for _, p := range extra {
		exists := false
		for _, q := range props {
			if q.Ns == p.Ns && q.Name == p.Name {
				exists = true
				break
			}
		}
		if !exists {
			props = append(props, p)
		}
	}
	return props
}

func (h *apiHelper) UpsertRiskTemplates(ctx context.Context, packageName string, riskTemplates []*proto.RiskTemplate) error {
	templates := ProtoToSdk(riskTemplates, RiskTemplateProtoToSdk)

	enriched := make([]types.RiskTemplate, 0)
	for _, temp := range *templates {
		temp = prepareRiskTemplateForUpsert(temp)
		if temp == nil {
			continue
		}

		enriched = append(enriched, *temp)
	}

	return h.client.RiskTemplate.Upsert(ctx, h.pluginName, packageName, enriched...)
}

func (h *apiHelper) UpsertSubjectTemplates(ctx context.Context, subjectTemplates []*proto.SubjectTemplate) error {
	templates := ProtoToSdk(subjectTemplates, SubjectTemplateProtoToSdk)

	enriched := make([]types.SubjectTemplate, 0)
	for _, temp := range *templates {
		if temp == nil {
			continue
		}

		temp.ID = optimisticUUID(temp.ID, map[string]string{
			"type":         "subject_template",
			"subject_type": temp.Type,
			"name":         temp.Name,
			"plugin_id":    h.pluginName,
		}).String()
		temp.SourceMode = "runtime-derived"
		temp.SelectorLabels = withPluginSelectorLabel(temp.SelectorLabels, h.pluginName)

		enriched = append(enriched, *temp)
	}
	return h.client.SubjectTemplate.Upsert(ctx, h.pluginName, enriched...)
}

func prepareRiskTemplateForUpsert(temp *types.RiskTemplate) *types.RiskTemplate {
	if temp == nil {
		return nil
	}

	isActive := true
	temp.IsActive = &isActive

	if temp.Remediation == nil {
		return temp
	}

	for i := range temp.Remediation.Tasks {
		temp.Remediation.Tasks[i].OrderIndex = i
	}

	return temp
}

func withPluginSelectorLabel(labels []types.SubjectTemplateSelectorLabel, pluginName string) []types.SubjectTemplateSelectorLabel {
	pluginSelectorLabel := "_plugin"
	result := make([]types.SubjectTemplateSelectorLabel, 0, len(labels)+1)
	replaced := false

	for _, label := range labels {
		if label.Key != pluginSelectorLabel {
			result = append(result, label)
			continue
		}

		if replaced {
			continue
		}

		label.Value = pluginName
		result = append(result, label)
		replaced = true
	}

	if replaced {
		return result
	}

	return append(result, types.SubjectTemplateSelectorLabel{
		Key:   pluginSelectorLabel,
		Value: pluginName,
	})
}

func appendSource(props []types.Property, source Source, referenceProp, digestProp string) []types.Property {
	if source.Reference == "" {
		return props
	}
	props = append(props, types.Property{Name: referenceProp, Value: source.Reference})
	if source.Digest != "" {
		props = append(props, types.Property{Name: digestProp, Value: source.Digest})
	}
	return props
}
