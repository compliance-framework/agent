package runner

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func dialServer(t *testing.T, server *grpc.Server) *GRPCApiHelperClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return &GRPCApiHelperClient{proto.NewApiHelperClient(conn)}
}

// streamRecorder is an ApiHelper that takes evidence one at a time and records each message
// exactly as it arrived over the stream.
type streamRecorder struct {
	recordingApiHelper
	mu       sync.Mutex
	received []*proto.Evidence
}

func (s *streamRecorder) NewEvidenceSender(context.Context) EvidenceSender { return s }
func (s *streamRecorder) Send(e *proto.Evidence) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.received = append(s.received, e)
}
func (s *streamRecorder) Close() error { return nil }

func TestStreamSendsEachEvaluationOnce(t *testing.T) {
	recorder := &streamRecorder{}
	client := dialServer(t, newApiHelperGRPCServer(recorder))

	first := &proto.PolicyEvaluation{PolicyPath: "/a", Input: []byte(`{"cluster":"big"}`)}
	second := &proto.PolicyEvaluation{PolicyPath: "/b", Input: []byte(`{"other":true}`)}
	evidence := []*proto.Evidence{
		evidenceFor("a1", first),
		evidenceFor("a2", first),
		evidenceFor("b1", second),
		evidenceFor("a3", first),
		evidenceFor("plain", nil),
	}
	require.NoError(t, client.CreateEvidence(context.Background(), evidence))

	require.Len(t, recorder.received, 5)
	got := func(i int) *proto.PolicyEvaluation { return recorder.received[i].GetPolicyEvaluation() }

	assert.Equal(t, `{"cluster":"big"}`, string(got(0).GetInput()), "first evidence of an evaluation carries its data")
	assert.NotEmpty(t, got(0).GetId())
	for _, i := range []int{1, 3} {
		assert.Equal(t, got(0).GetId(), got(i).GetId(), "later evidence refers to the same evaluation")
		assert.Empty(t, got(i).GetInput(), "later evidence does not repeat the data")
		assert.Empty(t, got(i).GetPolicyPath())
	}
	assert.Equal(t, `{"other":true}`, string(got(2).GetInput()))
	assert.NotEqual(t, got(0).GetId(), got(2).GetId())
	assert.Nil(t, got(4))
	assert.Equal(t, "a2", recorder.received[1].GetTitle(), "the rest of the evidence is sent unchanged")

	assert.Same(t, first, evidence[1].PolicyEvaluation, "the caller's evidence is not modified")
	assert.Equal(t, `{"cluster":"big"}`, string(evidence[1].PolicyEvaluation.Input))
}

// TestStreamFallsBackForAnOldAgent talks to an agent that serves only the unary
// CreateEvidence, as agents before the stream do.
func TestStreamFallsBackForAnOldAgent(t *testing.T) {
	impl := &recordingApiHelper{}
	helperServer := &GRPCApiHelperServer{}
	helperServer.SetImpl(impl)
	oldService := proto.ApiHelper_ServiceDesc
	oldService.Streams = nil
	server := grpc.NewServer()
	server.RegisterService(&oldService, helperServer)
	client := dialServer(t, server)

	evaluation := &proto.PolicyEvaluation{PolicyPath: "/a", Input: []byte(`{"x":1}`)}
	require.NoError(t, client.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("one", evaluation), evidenceFor("two", evaluation),
	}))
	require.Len(t, impl.evidence, 2)
	assert.Equal(t, `{"x":1}`, string(impl.evidence[1].GetPolicyEvaluation().GetInput()))
}

// TestAgentForwardsEvidenceAsItArrives sends evidence over the stream one message at a time
// and checks the agent has already sent each one to the API before the next is sent.
func TestAgentForwardsEvidenceAsItArrives(t *testing.T) {
	bundle := writeBundle(t, "a")
	api := &fakeAPI{}
	helper := newTestHelper(t, api, bundle)
	client := dialServer(t, newApiHelperGRPCServer(helper))

	stream, err := client.client.CreateEvidenceStream(context.Background())
	require.NoError(t, err)

	evidenceCount := func() int {
		api.mu.Lock()
		defer api.mu.Unlock()
		return len(api.evidence)
	}
	messages := []*proto.Evidence{
		evidenceFor("one", &proto.PolicyEvaluation{Id: "1", PolicyPath: bundle, Input: []byte(`{"n":1}`)}),
		evidenceFor("two", &proto.PolicyEvaluation{Id: "1"}),
		evidenceFor("three", nil),
	}
	for i, msg := range messages {
		require.NoError(t, stream.Send(&proto.CreateEvidenceStreamRequest{Evidence: msg}))
		require.Eventually(t, func() bool { return evidenceCount() == i+1 }, 2*time.Second, 5*time.Millisecond,
			"evidence %d reaches the API before the stream ends", i+1)
	}
	_, err = stream.CloseAndRecv()
	require.NoError(t, err)

	assert.Equal(t, []string{"one", "two", "three"}, sentTitles(api))
	assert.Len(t, api.uploads, 2, "the evaluation's artifacts are uploaded once")
	assert.Contains(t, api.evidence[1], "policy-artifacts", "a reference gets the digests of the evaluation it names")
}

func TestAgentRejectsAReferenceToAnUnsentEvaluation(t *testing.T) {
	api := &fakeAPI{}
	client := dialServer(t, newApiHelperGRPCServer(newTestHelper(t, api)))

	stream, err := client.client.CreateEvidenceStream(context.Background())
	require.NoError(t, err)
	require.NoError(t, stream.Send(&proto.CreateEvidenceStreamRequest{Evidence: evidenceFor("orphan", &proto.PolicyEvaluation{Id: "9"})}))
	require.NoError(t, stream.Send(&proto.CreateEvidenceStreamRequest{Evidence: evidenceFor("plain", nil)}))
	_, err = stream.CloseAndRecv()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "was not sent")
	assert.Equal(t, []string{"plain"}, sentTitles(api))
}

// TestStreamHoldsBackOnlyTheFailedEvaluation runs strict storage end to end through the
// plugin's client, the stream and the agent.
func TestStreamHoldsBackOnlyTheFailedEvaluation(t *testing.T) {
	good := writeBundle(t, "good")
	bad := writeBundle(t, "bad")
	api := &fakeAPI{artifactStatuses: []int{400}}
	client := dialServer(t, newApiHelperGRPCServer(newTestHelper(t, api, good, bad)))

	badEvaluation := &proto.PolicyEvaluation{PolicyPath: bad, Input: []byte(`{"n":1}`)}
	goodEvaluation := &proto.PolicyEvaluation{PolicyPath: good, Input: []byte(`{"n":2}`)}
	err := client.CreateEvidence(context.Background(), []*proto.Evidence{
		evidenceFor("bad-1", badEvaluation),
		evidenceFor("good-1", goodEvaluation),
		evidenceFor("bad-2", badEvaluation),
		evidenceFor("good-2", goodEvaluation),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), bad)
	assert.Equal(t, []string{"good-1", "good-2"}, sentTitles(api))
}
