package runner

import (
	"context"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct {
	client proto.RunnerClient
	broker *plugin.GRPCBroker
}

func (m *GRPCClient) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), req)
}

func (m *GRPCClient) PrepareForEval(req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {
	return m.client.PrepareForEval(context.Background(), req)
}

type AddHelper interface {
	Result() error
}
type GRPCAddHelperServer struct {
	// This is the real implementation
	Impl AddHelper
}

func (m *GRPCAddHelperServer) Result(ctx context.Context, req *proto.ResultRequest) (resp *proto.ResultResponse, err error) {
	err = m.Impl.Result()
	if err != nil {
		return nil, err
	}
	return &proto.ResultResponse{}, err
}

func (m *GRPCClient) Eval(bundlePath string, a AddHelper) (*proto.EvalResponse, error) {

	addHelperServer := &GRPCAddHelperServer{Impl: a}

	var s *grpc.Server
	serverFunc := func(opts []grpc.ServerOption) *grpc.Server {
		s = grpc.NewServer(opts...)
		proto.RegisterAddHelperServer(s, addHelperServer)

		return s
	}

	brokerID := m.broker.NextId()
	go m.broker.AcceptAndServe(brokerID, serverFunc)

	req := &proto.EvalRequest{BundlePath: bundlePath, AddServer: brokerID}
	resp, err := m.client.Eval(context.Background(), req)
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

type GRPCAddHelperClient struct{ client proto.AddHelperClient }

func (m *GRPCAddHelperClient) Result() error {
	_, err := m.client.Result(context.Background(), &proto.ResultRequest{})
	if err != nil {
		hclog.Default().Info("Harry WaZ eRe", err)
		return err
	}
	return err
}

func (m *GRPCServer) Eval(ctx context.Context, req *proto.EvalRequest) (*proto.EvalResponse, error) {
	conn, err := m.broker.Dial(req.AddServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	a := &GRPCAddHelperClient{proto.NewAddHelperClient(conn)}

	return m.Impl.Eval(req.BundlePath, a)
}
