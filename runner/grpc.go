package runner

import (
	"context"
	"github.com/compliance-framework/agent/runner/proto"
)

// GRPCClient is an implementation of KV that talks over RPC.
type GRPCClient struct{ client proto.RunnerClient }

func (m *GRPCClient) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return m.client.Configure(context.Background(), req)
}

func (m *GRPCClient) PrepareForEval(req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {
	return m.client.PrepareForEval(context.Background(), req)
}

func (m *GRPCClient) Eval(req *proto.EvalRequest) (*proto.EvalResponse, error) {
	resp, err := m.client.Eval(context.Background(), req)
	return resp, err
}

type GRPCServer struct {
	Impl Runner
}

func (m *GRPCServer) Configure(ctx context.Context, req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return m.Impl.Configure(req)
}

func (m *GRPCServer) PrepareForEval(ctx context.Context, req *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error) {
	return m.Impl.PrepareForEval(req)
}

func (m *GRPCServer) Eval(ctx context.Context, req *proto.EvalRequest) (*proto.EvalResponse, error) {
	return m.Impl.Eval(req)
}
