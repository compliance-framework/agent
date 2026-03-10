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
}

type GRPCApiHelperClient struct{ client proto.ApiHelperClient }

func (m *GRPCApiHelperClient) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	_, err := m.client.CreateEvidence(ctx, &proto.CreateEvidenceRequest{
		Evidence: evidence,
	})
	if err != nil {
		hclog.Default().Error("Error adding result", "error", err)
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
	return &proto.CreateEvidenceResponse{}, err
}

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct {
	client proto.RunnerClient
	broker *plugin.GRPCBroker

	apiHelperServer *GRPCApiHelperServer
	apiServerID     uint32
	apiServerOnce   sync.Once
}

type GRPCClientV2 struct {
	*GRPCClient
}

func (m *GRPCClient) startAPIServer(a ApiHelper) uint32 {
	m.apiServerOnce.Do(func() {
		m.apiHelperServer = &GRPCApiHelperServer{}

		serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
			s := grpc.NewServer(opts...)
			proto.RegisterApiHelperServer(s, m.apiHelperServer)
			return s
		}

		m.apiServerID = m.broker.NextId()
		go m.broker.AcceptAndServe(m.apiServerID, serverFunc)
	})

	m.apiHelperServer.SetImpl(a)

	return m.apiServerID
}

func (m *GRPCClient) Configure(request *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), request)
}

func (m *GRPCClientV2) Init(request *proto.InitRequest, a ApiHelper) (*proto.InitResponse, error) {
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
