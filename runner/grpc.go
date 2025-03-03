package runner

import (
	"context"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

type ApiHelper interface {
	CreateResult(*proto.AssessmentResult, string) error
}

type GRPCApiHelperClient struct{ client proto.ApiHelperClient }

func (m *GRPCApiHelperClient) CreateResult(assesmentResult *proto.AssessmentResult, streamId string) error {
	_, err := m.client.CreateResult(context.Background(), &proto.ResultRequest{
		Result:   assesmentResult,
		StreamId: streamId,
	})
	if err != nil {
		hclog.Default().Error("Error adding result", err)
	}
	return err
}

type GRPCApiHelperServer struct {
	// This is the real implementation
	Impl ApiHelper
}

func (m *GRPCApiHelperServer) CreateResult(ctx context.Context, req *proto.ResultRequest) (resp *proto.ResultResponse, err error) {
	err = m.Impl.CreateResult(req.Result, req.StreamId)
	if err != nil {
		return nil, err
	}
	return &proto.ResultResponse{}, err
}

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct {
	client proto.RunnerClient
	broker *plugin.GRPCBroker
}

func (m *GRPCClient) Configure(request *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), request)
}

func (m *GRPCClient) PrepareForEval(request *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {
	return m.client.PrepareForEval(context.Background(), request)
}

func (m *GRPCClient) Eval(request *proto.EvalRequest, a ApiHelper) (*proto.EvalResponse, error) {
	addHelperServer := &GRPCApiHelperServer{Impl: a}

	var s *grpc.Server
	serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
		s = grpc.NewServer(opts...)
		proto.RegisterApiHelperServer(s, addHelperServer)

		return s
	}

	brokerID := m.broker.NextId()
	go m.broker.AcceptAndServe(brokerID, serverFunc)

	request.AddServer = brokerID
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

func (m *GRPCServer) PrepareForEval(ctx context.Context, req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {
	return m.Impl.PrepareForEval(req)
}

func (m *GRPCServer) Eval(ctx context.Context, req *proto.EvalRequest) (*proto.EvalResponse, error) {
	conn, err := m.broker.Dial(req.AddServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	a := &GRPCApiHelperClient{proto.NewApiHelperClient(conn)}

	return m.Impl.Eval(req, a)
}
