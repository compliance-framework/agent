package runner

import (
	"context"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

type ApiHelper interface {
	CreateObservations(context.Context, []*proto.Observation) error
	CreateFindings(context.Context, []*proto.Finding) error
}

type GRPCApiHelperClient struct{ client proto.ApiHelperClient }

func (m *GRPCApiHelperClient) CreateObservations(ctx context.Context, observations []*proto.Observation) error {
	_, err := m.client.CreateObservations(ctx, &proto.CreateObservationsRequest{
		Observations: observations,
	})
	if err != nil {
		hclog.Default().Error("Error adding result", "error", err)
	}
	return err
}

func (m *GRPCApiHelperClient) CreateFindings(ctx context.Context, findings []*proto.Finding) error {
	_, err := m.client.CreateFindings(ctx, &proto.CreateFindingsRequest{
		Findings: findings,
	})
	if err != nil {
		hclog.Default().Error("Error adding result", "error", err)
	}
	return err
}

type GRPCApiHelperServer struct {
	// This is the real implementation
	Impl ApiHelper
}

func (m *GRPCApiHelperServer) CreateObservations(ctx context.Context, req *proto.CreateObservationsRequest) (resp *proto.CreateObservationsResponse, err error) {
	err = m.Impl.CreateObservations(ctx, req.GetObservations())
	if err != nil {
		return nil, err
	}
	return &proto.CreateObservationsResponse{}, err
}

func (m *GRPCApiHelperServer) CreateFindings(ctx context.Context, req *proto.CreateFindingsRequest) (resp *proto.CreateFindingsResponse, err error) {
	err = m.Impl.CreateFindings(ctx, req.GetFindings())
	if err != nil {
		return nil, err
	}
	return &proto.CreateFindingsResponse{}, err
}

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct {
	client proto.RunnerClient
	broker *plugin.GRPCBroker
}

func (m *GRPCClient) Configure(request *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), request)
}

func (m *GRPCClient) Eval(request *proto.EvalRequest, a ApiHelper) (*proto.EvalResponse, error) {
	apiHelperServer := &GRPCApiHelperServer{Impl: a}

	var s *grpc.Server
	serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
		s = grpc.NewServer(opts...)
		proto.RegisterApiHelperServer(s, apiHelperServer)

		return s
	}

	brokerID := m.broker.NextId()
	go m.broker.AcceptAndServe(brokerID, serverFunc)

	request.ApiServer = brokerID
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

func (m *GRPCServer) Eval(ctx context.Context, req *proto.EvalRequest) (*proto.EvalResponse, error) {
	conn, err := m.broker.Dial(req.ApiServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	a := &GRPCApiHelperClient{proto.NewApiHelperClient(conn)}

	return m.Impl.Eval(req, a)
}
