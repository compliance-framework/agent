package runner

import (
	"context"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

type Runner interface {
	Configure(request *proto.ConfigureRequest) (*proto.ConfigureResponse, error)
	PrepareForEval(request *proto.PrepareForEvalRequest) (*proto.PrepareForEvalResponse, error)
	Eval(request *proto.EvalRequest) (*proto.EvalResponse, error)
}

type RunnerGRPCPlugin struct {
	plugin.Plugin

	// Impl Injection
	Impl Runner
}

func (p *RunnerGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	proto.RegisterRunnerServer(s, &GRPCServer{Impl: p.Impl})
	return nil
}

func (p *RunnerGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{client: proto.NewRunnerClient(c)}, nil
}

var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "RUNNER_PLUGIN",
	MagicCookieValue: "AC755DCE-C118-481A-8EFA-18D8675D8122",
}

var PluginMap = map[string]plugin.Plugin{
	"runner": &RunnerGRPCPlugin{},
}
