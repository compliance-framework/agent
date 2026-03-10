package runner

import (
	"context"
	"testing"

	"github.com/compliance-framework/agent/runner/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type testRunnerV1 struct{}

func (t *testRunnerV1) Configure(request *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	return &proto.ConfigureResponse{}, nil
}

func (t *testRunnerV1) Eval(request *proto.EvalRequest, a ApiHelper) (*proto.EvalResponse, error) {
	return &proto.EvalResponse{}, nil
}

func TestGRPCServerInitReturnsUnimplementedForRunnerV1(t *testing.T) {
	server := &GRPCServer{Impl: &testRunnerV1{}}

	_, err := server.Init(context.Background(), &proto.InitRequest{})
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected code %v, got %v", codes.Unimplemented, status.Code(err))
	}
}
