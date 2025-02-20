package runner

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/compliance-framework/agent/runner/proto"
	"google.golang.org/grpc"
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

// Basic message struct without oscal goodness atm
// representing the streamed messages
type Message struct {
	Text   string
	IsLast bool
}

// Define the gRPC service interface manually
type ResultServiceServer interface {
	SendResult(ResultService_SendResultServer) error
}

// Define the server struct that will handle incoming streams
type ResultsGRPCInstance struct {
	msgChan    chan Message
	grpcServer *grpc.Server
}

// NewResultsGRPCInstance initializes the struct
func NewResultsGRPCInstance() *ResultsGRPCInstance {
	return &ResultsGRPCInstance{
		msgChan: make(chan Message, 100), // Buffered channel
	}
}

// SendResult handles streaming messages from clients
func (r *ResultsGRPCInstance) SendResult(stream ResultService_SendResultServer) error {
	for {
		msg, err := stream.Recv() // Receive a message from the client
		if err == io.EOF {
			close(r.msgChan) // End the stream when EOF is received
			return nil
		}
		if err != nil {
			return err
		}

		r.msgChan <- Message{Text: msg.Text, IsLast: msg.IsLast}

		// Close channel when last message arrives
		if msg.IsLast {
			close(r.msgChan)
			return nil
		}
	}
}

// StartGRPCServer initializes and runs the gRPC server
func (r *ResultsGRPCInstance) StartGRPCServer(wg *sync.WaitGroup) error {
	defer wg.Done()

	// Start a listener
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		return err
	}

	// Create gRPC server
	r.grpcServer = grpc.NewServer()

	// Register the service manually
	RegisterResultServiceServer(r.grpcServer, r)

	fmt.Println("ResultsGRPCInstance running on port 50051...")
	return r.grpcServer.Serve(lis)
}

// Implement ResultService_SendResultServer interface
type ResultService_SendResultServer interface {
	Send(*Message) error
	Recv() (*Message, error)
	grpc.ServerStream
}

// Manual service registration
func RegisterResultServiceServer(s *grpc.Server, srv ResultServiceServer) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "ResultService",
		HandlerType: (*ResultServiceServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "SendResult",
				Handler:       _ResultService_SendResult_Handler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "result_service",
	}, srv)
}

// Handler for the gRPC stream
func _ResultService_SendResult_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ResultServiceServer).SendResult(&resultServiceSendResultServer{stream})
}

// Helper struct to implement ResultService_SendResultServer
type resultServiceSendResultServer struct {
	grpc.ServerStream
}

func (x *resultServiceSendResultServer) Send(m *Message) error {
	return x.ServerStream.SendMsg(m)
}

func (x *resultServiceSendResultServer) Recv() (*Message, error) {
	m := new(Message)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}
