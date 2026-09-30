package runner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	protobuf "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// fakeAPI stands in for the API's artifact and evidence routes.
type fakeAPI struct {
	mu sync.Mutex
	// artifactStatuses are returned, in order, for artifact uploads; once used up, uploads
	// succeed.
	artifactStatuses []int
	uploads          []string
	evidence         []map[string]any
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)

	switch r.URL.Path {
	case "/api/agent/artifacts":
		f.uploads = append(f.uploads, r.Header.Get("Content-Type"))
		if len(f.artifactStatuses) > 0 {
			status := f.artifactStatuses[0]
			f.artifactStatuses = f.artifactStatuses[1:]
			w.WriteHeader(status)
			return
		}
		sum := sha256.Sum256(body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"digest":"sha256:` + hex.EncodeToString(sum[:]) + `","mediaType":"` + r.Header.Get("Content-Type") + `"}`))
	case "/api/evidence":
		var e map[string]any
		_ = json.Unmarshal(body, &e)
		f.evidence = append(f.evidence, e)
		w.WriteHeader(http.StatusCreated)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newTestHelper(t *testing.T, api *fakeAPI, policyPaths ...string) *apiHelper {
	t.Helper()
	server := httptest.NewServer(api)
	t.Cleanup(server.Close)
	client := sdk.NewClient(server.Client(), &sdk.Config{BaseURL: server.URL})
	helper := NewApiHelper(hclog.NewNullLogger(), client, map[string]string{"_agent": "test"}, "test-plugin", WithPolicyPaths(policyPaths))
	helper.artifacts.retryDelay = time.Millisecond
	return helper
}

func writeBundle(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".rego"), []byte("package compliance_framework."+name+"\n\ntitle := \""+name+"\"\n"), 0o644))
	return dir
}

func evidenceFor(title string, evaluation *proto.PolicyEvaluation) *proto.Evidence {
	return &proto.Evidence{UUID: "11111111-1111-1111-1111-111111111111", Title: title, PolicyEvaluation: evaluation}
}

func sentTitles(api *fakeAPI) []string {
	var titles []string
	for _, e := range api.evidence {
		titles = append(titles, e["title"].(string))
	}
	return titles
}

func TestCreateEvidenceUploadsOncePerEvaluation(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)

	// Two evidence records from one evaluation, as separate copies, as they arrive over gRPC.
	input := []byte(`{"PermitRootLogin":"yes"}`)
	policyData := []byte(`{"allowed":["deploy"]}`)
	err := helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("one", &proto.PolicyEvaluation{PolicyPath: bundle, Input: input, PolicyData: policyData}),
		evidenceFor("two", &proto.PolicyEvaluation{PolicyPath: bundle, Input: input, PolicyData: policyData}),
	})
	require.NoError(t, err)

	assert.Equal(t, []string{sdk.ArtifactMediaTypePolicyBundle, sdk.ArtifactMediaTypeJSON, sdk.ArtifactMediaTypeJSON}, api.uploads)
	require.Len(t, api.evidence, 2)
	for _, e := range api.evidence {
		refs, ok := e["policy-artifacts"].(map[string]any)
		require.True(t, ok, "evidence must carry policy-artifacts: %v", e)
		assert.NotEmpty(t, refs["bundle-digest"])
		assert.NotEmpty(t, refs["input-digest"])
		assert.NotEmpty(t, refs["policy-data-digest"])
		raw, _ := json.Marshal(e)
		assert.NotContains(t, string(raw), "PermitRootLogin", "raw input must not be forwarded with the evidence")
	}

	// A later run with unchanged content uploads nothing again.
	err = helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("three", &proto.PolicyEvaluation{PolicyPath: bundle, Input: input, PolicyData: policyData}),
	})
	require.NoError(t, err)
	assert.Len(t, api.uploads, 3)
}

func TestCreateEvidenceWithoutEvaluationIsUnchanged(t *testing.T) {
	api := &fakeAPI{}
	helper := newTestHelper(t, api)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{evidenceFor("old plugin", nil)}))
	assert.Empty(t, api.uploads)
	require.Len(t, api.evidence, 1)
	assert.NotContains(t, api.evidence[0], "policy-artifacts")
}

func TestCreateEvidenceUnderAnOldAPISendsEvidenceWithoutArtifacts(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{artifactStatuses: []int{http.StatusNotFound}}
	helper := newTestHelper(t, api, bundle)

	err := helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("one", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	})
	require.NoError(t, err)
	require.Len(t, api.evidence, 1)
	assert.NotContains(t, api.evidence[0], "policy-artifacts")

	// It does not keep asking an old API on every run...
	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("two", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	}))
	assert.Len(t, api.uploads, 1)

	// ...but checks again later, so an upgraded API is picked up.
	helper.artifacts.now = func() time.Time { return time.Now().Add(artifactsUnsupportedRecheck + time.Minute) }
	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("three", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	}))
	assert.Contains(t, api.evidence[2], "policy-artifacts")
}

func TestCreateEvidenceRetriesTemporaryFailures(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{artifactStatuses: []int{http.StatusInternalServerError, http.StatusServiceUnavailable}}
	helper := newTestHelper(t, api, bundle)

	err := helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("one", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	})
	require.NoError(t, err)
	assert.Len(t, api.uploads, 4, "two failed bundle attempts, the successful one, then the input")
	require.Len(t, api.evidence, 1)
	assert.Contains(t, api.evidence[0], "policy-artifacts")
}

// artifactsOf returns each sent evidence's policy-artifacts by title, nil where it has none.
func artifactsOf(api *fakeAPI) map[string]any {
	out := map[string]any{}
	for _, e := range api.evidence {
		out[e["title"].(string)] = e["policy-artifacts"]
	}
	return out
}

func TestCreateEvidenceFallsBackWhenArtifactsCannotBeStored(t *testing.T) {
	good := writeBundle(t, "good")
	bad := writeBundle(t, "bad")

	for name, tc := range map[string]struct {
		statuses    []int
		allowed     []string
		wantUploads int
	}{
		"server keeps failing after retries": {
			statuses:    []int{500, 500, 500},
			allowed:     []string{good, bad},
			wantUploads: 3 + 2,
		},
		"content rejected is not retried": {
			statuses:    []int{http.StatusBadRequest},
			allowed:     []string{good, bad},
			wantUploads: 1 + 2,
		},
		"too large is not retried": {
			statuses:    []int{http.StatusRequestEntityTooLarge},
			allowed:     []string{good, bad},
			wantUploads: 1 + 2,
		},
		"path not given to the plugin": {
			allowed:     []string{good},
			wantUploads: 2,
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeAPI{artifactStatuses: tc.statuses}
			helper := newTestHelper(t, api, tc.allowed...)

			// The failing evaluation comes first, so its failures consume the statuses.
			err := helper.CreateEvidence(context.Background(), []*proto.Evidence{
				evidenceFor("bad", &proto.PolicyEvaluation{PolicyPath: bad, Input: []byte(`{"n":1}`)}),
				evidenceFor("good", &proto.PolicyEvaluation{PolicyPath: good, Input: []byte(`{"n":2}`)}),
			})
			require.NoError(t, err, "evidence is never lost because its artifacts could not be stored")

			assert.Equal(t, []string{"bad", "good"}, sentTitles(api), "all evidence is sent")
			sent := artifactsOf(api)
			assert.Nil(t, sent["bad"], "evidence whose artifacts failed is sent without digests, as before")
			assert.NotNil(t, sent["good"], "other evaluations keep their digests")
			assert.Len(t, api.uploads, tc.wantUploads)
		})
	}
}

func TestCreateEvidenceRetriesBeforeFallingBack(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{artifactStatuses: []int{http.StatusServiceUnavailable, http.StatusTooManyRequests}}
	helper := newTestHelper(t, api, bundle)

	require.NoError(t, helper.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("one", &proto.PolicyEvaluation{PolicyPath: bundle, Input: []byte(`{}`)}),
	}))
	assert.NotNil(t, artifactsOf(api)["one"], "a temporary failure that clears on retry keeps the evidence replayable")
}

// TestNewPluginEvidenceDecodesUnderAnOldAgent decodes evidence carrying a PolicyEvaluation
// with the Evidence schema as it was before the field existed, as an old agent would.
func TestNewPluginEvidenceDecodesUnderAnOldAgent(t *testing.T) {
	fileProto := protodesc.ToFileDescriptorProto(proto.File_runner_proto_types_proto)
	for _, message := range fileProto.MessageType {
		if message.GetName() != "Evidence" {
			continue
		}
		var fields []*descriptorpb.FieldDescriptorProto
		for _, field := range message.Field {
			if field.GetName() != "PolicyEvaluation" {
				fields = append(fields, field)
			}
		}
		message.Field = fields
		message.OneofDecl = nil
		for _, field := range message.Field {
			field.OneofIndex = nil
		}
	}
	fileProto.Name = protobuf.String("old/" + fileProto.GetName())
	oldFile, err := protodesc.NewFile(fileProto, protoregistry.GlobalFiles)
	require.NoError(t, err)
	oldEvidence := oldFile.Messages().ByName("Evidence")
	require.Nil(t, oldEvidence.Fields().ByName("PolicyEvaluation"))

	wire, err := protobuf.Marshal(evidenceFor("from a new plugin", &proto.PolicyEvaluation{PolicyPath: "/p", Input: []byte(`{"a":1}`)}))
	require.NoError(t, err)

	decoded := dynamicpb.NewMessage(oldEvidence)
	require.NoError(t, protobuf.Unmarshal(wire, decoded))
	assert.Equal(t, "from a new plugin", decoded.Get(oldEvidence.Fields().ByName("Title")).String())
}

// TestApiHelperServerAcceptsLargeEvidence sends a CreateEvidence call well above gRPC's
// 4 MiB default through the server the agent serves plugins on.
func TestApiHelperServerAcceptsLargeEvidence(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	impl := &recordingApiHelper{}
	server := newApiHelperGRPCServer(impl)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	input := bytes.Repeat([]byte("a"), 10<<20)
	evaluation := &proto.PolicyEvaluation{PolicyPath: "/p", Input: input}
	client := &GRPCApiHelperClient{proto.NewApiHelperClient(conn)}
	err = client.CreateEvidence(context.Background(), []*proto.Evidence{evidenceFor("one", evaluation), evidenceFor("two", evaluation)})
	require.NoError(t, err)
	require.Len(t, impl.evidence, 2)
	assert.Len(t, impl.evidence[1].GetPolicyEvaluation().GetInput(), len(input))
}

type recordingApiHelper struct {
	evidence []*proto.Evidence
}

func (r *recordingApiHelper) CreateEvidence(_ context.Context, evidence []*proto.Evidence) error {
	r.evidence = evidence
	return nil
}
func (r *recordingApiHelper) UpsertRiskTemplates(context.Context, string, []*proto.RiskTemplate) error {
	return nil
}
func (r *recordingApiHelper) UpsertSubjectTemplates(context.Context, []*proto.SubjectTemplate) error {
	return nil
}

// TestGeneratedEvidenceReachesTheAPIWithArtifacts runs a real PolicyProcessor, then the
// agent's CreateEvidence: the evidence arrives with digests of exactly what was evaluated.
func TestGeneratedEvidenceReachesTheAPIWithArtifacts(t *testing.T) {
	bundle := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bundle, "wget.rego"), []byte(`package compliance_framework.wget

title := "wget is the approved version"

violation contains {"id": "wget-version"} if input.wget != data.allowed_versions.wget
`), 0o644))
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)

	processor := policyManager.NewPolicyProcessor(hclog.NewNullLogger(), nil, nil, nil, nil, nil, nil,
		map[string]interface{}{"allowed_versions": map[string]interface{}{"wget": "1.20.3"}})
	evidences, err := processor.GenerateResults(context.Background(), bundle, map[string]interface{}{"wget": "1.19.0"})
	require.NoError(t, err)
	require.NoError(t, helper.CreateEvidence(context.Background(), evidences))

	require.Len(t, api.evidence, 1)
	refs := api.evidence[0]["policy-artifacts"].(map[string]any)
	inputSum := sha256.Sum256([]byte(`{"wget":"1.19.0"}`))
	assert.Equal(t, "sha256:"+hex.EncodeToString(inputSum[:]), refs["input-digest"])
	assert.NotEmpty(t, refs["policy-data-digest"])
	assert.True(t, strings.HasPrefix(refs["bundle-digest"].(string), "sha256:"))
}
