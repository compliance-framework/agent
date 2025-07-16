package runner

import (
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/compliance-framework/api/sdk"
	"github.com/compliance-framework/api/sdk/types"
	"github.com/google/uuid"
)

func SubjectTypeFromEnum(in proto.SubjectType) string {
	subjectTypes := map[proto.SubjectType]string{
		proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM: "InventoryItem",
		proto.SubjectType_SUBJECT_TYPE_COMPONENT:      "Component",
	}

	if val, ok := subjectTypes[in]; ok {
		return val
	}
	return ""
}

func EvidenceStatusStateFromEnum(in proto.EvidenceStatusState) string {
	subjectTypes := map[proto.EvidenceStatusState]string{
		proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_SATISFIED:     "satisfied",
		proto.EvidenceStatusState_EVIDENCE_STATUS_STATE_NOT_SATISFIED: "not-satisfied",
	}

	if val, ok := subjectTypes[in]; ok {
		return val
	}
	return ""
}

func ProtoToSdk[I any, O any](ins []I, transformer func(I) O) *[]O {
	results := make([]O, 0)
	for _, in := range ins {
		results = append(results, transformer(in))
	}
	return &results
}

func optimisticUUID(idString string, seedMap map[string]string) uuid.UUID {
	if idString != "" {
		id, err := uuid.Parse(idString)
		if err == nil {
			return id
		}
	}

	if len(seedMap) == 0 {
		return uuid.New()
	}

	uid, err := sdk.SeededUUID(seedMap)
	if err != nil {
		return uuid.New()
	}

	return uid
}

func LinkProtoToSdk(link *proto.Link) types.Link {
	return types.Link{
		Href:             link.GetHref(),
		MediaType:        link.GetMediaType(),
		Rel:              link.GetRel(),
		ResourceFragment: link.GetResourceFragment(),
		Text:             link.GetText(),
	}
}

func PropertyProtoToSdk(property *proto.Property) types.Property {
	return types.Property{
		Class:   property.GetClass(),
		Group:   property.GetGroup(),
		Name:    property.GetName(),
		Ns:      property.GetNs(),
		Remarks: property.GetRemarks(),
		UUID:    property.GetUuid(),
		Value:   property.GetValue(),
	}
}

func SubjectProtoToSdk(subject *proto.Subject) types.Subject {
	return types.Subject{
		Identifier:  subject.GetIdentifier(),
		Type:        SubjectTypeFromEnum(subject.GetType()),
		Description: subject.GetDescription(),
		Remarks:     subject.GetRemarks(),
		Props:       *ProtoToSdk(subject.GetProps(), PropertyProtoToSdk),
		Links:       *ProtoToSdk(subject.GetLinks(), LinkProtoToSdk),
	}
}

func InventoryItemProtoToSdk(in *proto.InventoryItem) types.InventoryItem {
	return types.InventoryItem{
		Identifier:  in.GetIdentifier(),
		Type:        in.GetType(),
		Title:       in.GetTitle(),
		Description: in.GetDescription(),
		Remarks:     in.GetRemarks(),
		Props:       *ProtoToSdk(in.GetProps(), PropertyProtoToSdk),
		Links:       *ProtoToSdk(in.GetLinks(), LinkProtoToSdk),
		ImplementedComponents: *ProtoToSdk(in.GetImplementedComponents(), func(in *proto.InventoryItemImplementedComponent) types.ComponentIdentifier {
			return types.ComponentIdentifier{Identifier: in.GetIdentifier()}
		}),
	}
}

func OriginProtoToSdk(origin *proto.Origin) types.Origin {
	return types.Origin{
		Actors: *ProtoToSdk(origin.GetActors(), OriginActorProtoToSdk),
	}
}

func OriginActorProtoToSdk(actor *proto.OriginActor) types.OriginActor {
	result := types.OriginActor{
		UUID: optimisticUUID(actor.GetUUID(), map[string]string{
			"type":       "actor",
			"actor-type": actor.GetType(),
			"title":      actor.GetTitle(),
		}),
		RoleId: actor.GetRoleId(),
		Type:   actor.GetType(),
		Title:  actor.GetTitle(),
		Links:  ProtoToSdk(actor.GetLinks(), LinkProtoToSdk),
		Props:  ProtoToSdk(actor.GetProps(), PropertyProtoToSdk),
	}
	return result
}

func StepProtoToSdk(step *proto.Step) types.Step {
	result := types.Step{
		UUID: optimisticUUID(step.GetUUID(), map[string]string{
			"type":  "step",
			"title": step.GetTitle(),
		}),
		Title:       step.GetTitle(),
		Description: step.GetDescription(),
		Remarks:     step.GetRemarks(),
		Props:       *ProtoToSdk(step.GetProps(), PropertyProtoToSdk),
		Links:       *ProtoToSdk(step.GetLinks(), LinkProtoToSdk),
	}
	return result
}

func ActivityProtoToSdk(activity *proto.Activity) types.Activity {
	return types.Activity{
		UUID: optimisticUUID(activity.GetUUID(), map[string]string{
			"type":        "activity",
			"title":       activity.GetTitle(),
			"description": activity.GetDescription(),
		}),
		Title:       activity.GetTitle(),
		Description: activity.GetDescription(),
		Remarks:     activity.GetRemarks(),
		Steps:       *ProtoToSdk(activity.GetSteps(), StepProtoToSdk),
		Props:       *ProtoToSdk(activity.GetProps(), PropertyProtoToSdk),
		Links:       *ProtoToSdk(activity.GetLinks(), LinkProtoToSdk),
	}
}

func ProtocolProtoToSdk(protocol *proto.Protocol) types.Protocol {
	result := types.Protocol{
		UUID: optimisticUUID(protocol.GetUUID(), map[string]string{
			"type":  "protocol",
			"name":  protocol.GetName(),
			"title": protocol.GetTitle(),
		}),
		Name:  protocol.GetName(),
		Title: protocol.GetTitle(),
	}
	for _, r := range protocol.PortRanges {
		protocol.PortRanges = append(protocol.PortRanges, r)
	}
	return result
}

func ComponentProtoToSdk(comp *proto.Component) types.Component {
	return types.Component{
		Identifier:  comp.GetIdentifier(),
		Type:        comp.GetType(),
		Title:       comp.GetTitle(),
		Description: comp.GetDescription(),
		Remarks:     comp.GetRemarks(),
		Purpose:     comp.GetPurpose(),
		Protocols:   *ProtoToSdk(comp.GetProtocols(), ProtocolProtoToSdk),
		Props:       *ProtoToSdk(comp.GetProps(), PropertyProtoToSdk),
		Links:       *ProtoToSdk(comp.GetLinks(), LinkProtoToSdk),
	}
}

func EvidenceProtoToSdk(evidence *proto.Evidence) *types.Evidence {
	remarks := evidence.GetRemarks()
	expires := evidence.GetExpires().AsTime()

	return &types.Evidence{
		UUID:           uuid.MustParse(evidence.GetUUID()),
		Title:          evidence.GetTitle(),
		Description:    evidence.GetDescription(),
		Remarks:        &remarks,
		Labels:         evidence.GetLabels(),
		Start:          evidence.GetStart().AsTime(),
		End:            evidence.GetEnd().AsTime(),
		Expires:        &expires,
		Props:          *ProtoToSdk(evidence.GetProps(), PropertyProtoToSdk),
		Links:          *ProtoToSdk(evidence.GetLinks(), LinkProtoToSdk),
		Origins:        *ProtoToSdk(evidence.GetOrigins(), OriginProtoToSdk),
		Activities:     *ProtoToSdk(evidence.GetActivities(), ActivityProtoToSdk),
		InventoryItems: *ProtoToSdk(evidence.GetInventoryItems(), InventoryItemProtoToSdk),
		Components:     *ProtoToSdk(evidence.GetComponents(), ComponentProtoToSdk),
		Subjects:       *ProtoToSdk(evidence.GetSubjects(), SubjectProtoToSdk),
		Status: types.ObjectiveStatus{
			Reason:  evidence.GetStatus().GetReason(),
			Remarks: evidence.GetStatus().GetRemarks(),
			State:   EvidenceStatusStateFromEnum(evidence.GetStatus().GetState()),
		},
	}
}
