package runner

import (
	"context"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

type Runner interface {
	Configure(request *proto.ConfigureRequest) (*proto.ConfigureResponse, error)
	Eval(request *proto.EvalRequest, a ApiHelper) (*proto.EvalResponse, error)
}

type RunnerV2 interface {
	Runner
	Init(request *proto.InitRequest, a ApiHelper) (*proto.InitResponse, error)
}

type RunnerGRPCPlugin struct {
	plugin.Plugin

	// Impl Injection
	Impl Runner
}

type RunnerV2GRPCPlugin struct {
	plugin.Plugin

	// Impl Injection
	Impl RunnerV2
}

func registerRunnerServer(broker *plugin.GRPCBroker, s *grpc.Server, impl Runner) error {
	proto.RegisterRunnerServer(s, &GRPCServer{
		Impl:   impl,
		broker: broker,
	})
	return nil
}

func newGRPCClient(broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return &GRPCClient{
		client: proto.NewRunnerClient(c),
		broker: broker,
	}, nil
}

func (p *RunnerGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	return registerRunnerServer(broker, s, p.Impl)
}

func (p *RunnerGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return newGRPCClient(broker, c)
}

func (p *RunnerV2GRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	return registerRunnerServer(broker, s, p.Impl)
}

func (p *RunnerV2GRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return newGRPCClient(broker, c)
}

var HandshakeConfig = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "RUNNER_PLUGIN",
	MagicCookieValue: "AC755DCE-C118-481A-8EFA-18D8675D8122",
}

var PluginMap = map[string]plugin.Plugin{
	"runner": &RunnerGRPCPlugin{},
}
