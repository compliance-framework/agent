package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
)

// Evidence travels from plugin to agent as a client stream, one message per evidence, so no
// single call carries the whole batch and the agent handles each evidence as it arrives.
// Each evaluation's PolicyEvaluation, which can be large, is sent in full once per stream;
// later evidence from the same evaluation refers to it by Id.

// EvidenceSender takes evidence one at a time. Send handles each evidence as it arrives;
// Close reports every failure since the sender was opened.
type EvidenceSender interface {
	Send(*proto.Evidence)
	Close() error
}

// EvidenceStreamer is implemented by ApiHelpers that can take evidence one at a time. The
// agent's helper does; other ApiHelpers are given the whole batch through CreateEvidence.
type EvidenceStreamer interface {
	NewEvidenceSender(context.Context) EvidenceSender
}

// CreateEvidence streams evidence to the agent. Against an agent that predates the stream,
// it falls back to a single CreateEvidence call.
func (m *GRPCApiHelperClient) CreateEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	err := m.streamEvidence(ctx, evidence)
	if status.Code(err) == codes.Unimplemented {
		_, err = m.client.CreateEvidence(ctx, &proto.CreateEvidenceRequest{Evidence: evidence})
	}
	if err != nil {
		hclog.Default().Error("Error adding result", "error", err)
	}
	return err
}

func (m *GRPCApiHelperClient) streamEvidence(ctx context.Context, evidence []*proto.Evidence) error {
	stream, err := m.client.CreateEvidenceStream(ctx)
	if err != nil {
		return err
	}

	ids := map[*proto.PolicyEvaluation]string{}
	for _, e := range evidence {
		msg := e
		if evaluation := e.GetPolicyEvaluation(); evaluation != nil {
			if id, sent := ids[evaluation]; sent {
				msg = withEvaluation(e, &proto.PolicyEvaluation{Id: id})
			} else {
				id = strconv.Itoa(len(ids) + 1)
				ids[evaluation] = id
				msg = withEvaluation(e, &proto.PolicyEvaluation{
					Id:         id,
					PolicyPath: evaluation.GetPolicyPath(),
					Input:      evaluation.GetInput(),
					PolicyData: evaluation.GetPolicyData(),
				})
			}
		}
		if err := stream.Send(&proto.CreateEvidenceStreamRequest{Evidence: msg}); err != nil {
			if errors.Is(err, io.EOF) {
				// The agent ended the stream; its reason comes from CloseAndRecv.
				break
			}
			return err
		}
	}
	_, err = stream.CloseAndRecv()
	return err
}

// withEvaluation returns a shallow copy of e with its PolicyEvaluation replaced. The
// caller's evidence is left untouched and nothing large is copied.
func withEvaluation(e *proto.Evidence, evaluation *proto.PolicyEvaluation) *proto.Evidence {
	out := &proto.Evidence{}
	src, dst := e.ProtoReflect(), out.ProtoReflect()
	field := src.Descriptor().Fields().ByName("PolicyEvaluation")
	src.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd != field {
			dst.Set(fd, v)
		}
		return true
	})
	out.PolicyEvaluation = evaluation
	return out
}

func (m *GRPCApiHelperServer) CreateEvidenceStream(stream proto.ApiHelper_CreateEvidenceStreamServer) error {
	m.mu.RLock()
	impl := m.Impl
	m.mu.RUnlock()
	if impl == nil {
		return status.Error(codes.FailedPrecondition, "API helper server is not configured")
	}

	if streamer, ok := impl.(EvidenceStreamer); ok {
		sender := streamer.NewEvidenceSender(stream.Context())
		for {
			req, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return errors.Join(err, sender.Close())
			}
			sender.Send(req.GetEvidence())
		}
		if err := sender.Close(); err != nil {
			return err
		}
		return stream.SendAndClose(&proto.CreateEvidenceResponse{})
	}

	// An ApiHelper that takes only batches gets the whole stream, with evaluations sent by
	// reference restored to their full content.
	evaluations := map[string]*proto.PolicyEvaluation{}
	var batch []*proto.Evidence
	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		e := req.GetEvidence()
		if evaluation := e.GetPolicyEvaluation(); evaluation != nil {
			if full, ok := resolveEvaluation(evaluations, evaluation); ok {
				e = withEvaluation(e, full)
			} else {
				return status.Errorf(codes.InvalidArgument, "evidence refers to policy evaluation %q before it was sent", evaluation.GetId())
			}
		}
		batch = append(batch, e)
	}
	if err := impl.CreateEvidence(stream.Context(), batch); err != nil {
		return err
	}
	return stream.SendAndClose(&proto.CreateEvidenceResponse{})
}

// resolveEvaluation records an evaluation sent in full and returns it, or returns the
// evaluation an Id-only reference names.
func resolveEvaluation(seen map[string]*proto.PolicyEvaluation, evaluation *proto.PolicyEvaluation) (*proto.PolicyEvaluation, bool) {
	if !isReference(evaluation) {
		if id := evaluation.GetId(); id != "" {
			seen[id] = evaluation
		}
		return evaluation, true
	}
	full, ok := seen[evaluation.GetId()]
	return full, ok
}

// isReference reports whether evaluation only names one sent earlier in the stream.
func isReference(evaluation *proto.PolicyEvaluation) bool {
	return evaluation.GetId() != "" && evaluation.GetPolicyPath() == "" && len(evaluation.GetInput()) == 0
}

var errUnknownEvaluation = errors.New("evidence refers to a policy evaluation that was not sent")

func unknownEvaluation(id string) error {
	return fmt.Errorf("%w: %q", errUnknownEvaluation, id)
}
