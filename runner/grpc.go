package runner

import (
	"context"
	"sync"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ApiHelper interface {
	CreateEvidence(context.Context, []*proto.Evidence) error
	UpsertRiskTemplates(context.Context, string, []*proto.RiskTemplate) error
	UpsertSubjectTemplates(context.Context, []*proto.SubjectTemplate) error
}

// MaxApiHelperMessageBytes bounds one message from a plugin to the agent. Evidence is
// streamed one per message, so this bounds a single evidence, whose PolicyEvaluation may
// carry a large input such as a whole cluster; gRPC's 4 MiB default is too small for that.
const MaxApiHelperMessageBytes = 256 << 20

type GRPCApiHelperClient struct{ client proto.ApiHelperClient }

func (m *GRPCApiHelperClient) UpsertRiskTemplates(ctx context.Context, packageName string, riskTemplates []*proto.RiskTemplate) error {
	_, err := m.client.UpsertRiskTemplates(ctx, &proto.UpsertRiskTemplatesRequest{
		PackageName:   packageName,
		RiskTemplates: riskTemplates,
	})
	if err != nil {
		hclog.Default().Error("Error upserting risk template", "error", err)
	}
	return err
}

func (m *GRPCApiHelperClient) UpsertSubjectTemplates(ctx context.Context, subjectTemplates []*proto.SubjectTemplate) error {
	_, err := m.client.UpsertSubjectTemplates(ctx, &proto.UpsertSubjectTemplatesRequest{
		SubjectTemplates: subjectTemplates,
	})
	if err != nil {
		hclog.Default().Error("Error upserting subject template", "error", err)
	}
	return err
}

type GRPCApiHelperServer struct {
	mu sync.RWMutex

	// This is the real implementation
	Impl ApiHelper
}

func (m *GRPCApiHelperServer) SetImpl(impl ApiHelper) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Impl = impl
}

func (m *GRPCApiHelperServer) CreateEvidence(ctx context.Context, req *proto.CreateEvidenceRequest) (resp *proto.CreateEvidenceResponse, err error) {
	m.mu.RLock()
	impl := m.Impl
	m.mu.RUnlock()
	if impl == nil {
		return nil, status.Error(codes.FailedPrecondition, "API helper server is not configured")
	}

	err = impl.CreateEvidence(ctx, req.GetEvidence())
	if err != nil {
		return nil, err
	}
	return &proto.CreateEvidenceResponse{}, nil
}

func (m *GRPCApiHelperServer) UpsertRiskTemplates(ctx context.Context, req *proto.UpsertRiskTemplatesRequest) (resp *proto.UpsertRiskTemplatesResponse, err error) {
	m.mu.RLock()
	impl := m.Impl
	m.mu.RUnlock()
	if impl == nil {
		return nil, status.Error(codes.FailedPrecondition, "API helper server is not configured")
	}

	err = impl.UpsertRiskTemplates(ctx, req.PackageName, req.GetRiskTemplates())
	if err != nil {
		return nil, err
	}
	return &proto.UpsertRiskTemplatesResponse{}, nil
}

func (m *GRPCApiHelperServer) UpsertSubjectTemplates(ctx context.Context, req *proto.UpsertSubjectTemplatesRequest) (resp *proto.UpsertSubjectTemplatesResponse, err error) {
	m.mu.RLock()
	impl := m.Impl
	m.mu.RUnlock()
	if impl == nil {
		return nil, status.Error(codes.FailedPrecondition, "API helper server is not configured")
	}

	err = impl.UpsertSubjectTemplates(ctx, req.GetSubjectTemplates())
	if err != nil {
		return nil, err
	}
	return &proto.UpsertSubjectTemplatesResponse{}, nil
}

// GRPCClient implements Runner over go-plugin gRPC.
type GRPCClient struct {
	client proto.RunnerClient
	broker *plugin.GRPCBroker
}

// newApiHelperGRPCServer serves a to plugins.
func newApiHelperGRPCServer(a ApiHelper, opts ...grpc.ServerOption) *grpc.Server {
	apiHelperServer := &GRPCApiHelperServer{}
	apiHelperServer.SetImpl(a)

	s := grpc.NewServer(append(opts, grpc.MaxRecvMsgSize(MaxApiHelperMessageBytes))...)
	proto.RegisterApiHelperServer(s, apiHelperServer)
	return s
}

func (m *GRPCClient) startAPIServer(a ApiHelper) uint32 {
	serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
		return newApiHelperGRPCServer(a, opts...)
	}

	apiServerID := m.broker.NextId()
	go m.broker.AcceptAndServe(apiServerID, serverFunc)

	return apiServerID
}

func (m *GRPCClient) Configure(request *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), request)
}

func (m *GRPCClient) Init(request *proto.InitRequest, a ApiHelper) (*proto.InitResponse, error) {
	request.ApiServer = m.startAPIServer(a)
	resp, err := m.client.Init(context.Background(), request)
	return resp, err
}

func (m *GRPCClient) Eval(request *proto.EvalRequest, a ApiHelper) (*proto.EvalResponse, error) {
	request.ApiServer = m.startAPIServer(a)
	resp, err := m.client.Eval(context.Background(), request)
	return resp, err
}

type GRPCServer struct {
	Impl   Runner
	broker *plugin.GRPCBroker
}

func (m *GRPCServer) Configure(ctx context.Context, req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return m.Impl.Configure(req)
}

func (m *GRPCServer) Init(ctx context.Context, req *proto.InitRequest) (*proto.InitResponse, error) {
	runnerV2, ok := m.Impl.(RunnerV2)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "Init is only supported for protocol v2 plugins")
	}

	conn, err := m.broker.Dial(req.ApiServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	a := &GRPCApiHelperClient{proto.NewApiHelperClient(conn)}
	return runnerV2.Init(req, a)
}

func (m *GRPCServer) Eval(ctx context.Context, req *proto.EvalRequest) (*proto.EvalResponse, error) {
	conn, err := m.broker.Dial(req.ApiServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	a := &GRPCApiHelperClient{proto.NewApiHelperClient(conn)}

	return m.Impl.Eval(req, a)
}
