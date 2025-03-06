// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        (unknown)
// source: runner/proto/runner.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ExecutionStatus int32

const (
	ExecutionStatus_SUCCESS ExecutionStatus = 0
	ExecutionStatus_FAILURE ExecutionStatus = 1
)

// Enum value maps for ExecutionStatus.
var (
	ExecutionStatus_name = map[int32]string{
		0: "SUCCESS",
		1: "FAILURE",
	}
	ExecutionStatus_value = map[string]int32{
		"SUCCESS": 0,
		"FAILURE": 1,
	}
)

func (x ExecutionStatus) Enum() *ExecutionStatus {
	p := new(ExecutionStatus)
	*p = x
	return p
}

func (x ExecutionStatus) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (ExecutionStatus) Descriptor() protoreflect.EnumDescriptor {
	return file_runner_proto_runner_proto_enumTypes[0].Descriptor()
}

func (ExecutionStatus) Type() protoreflect.EnumType {
	return &file_runner_proto_runner_proto_enumTypes[0]
}

func (x ExecutionStatus) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use ExecutionStatus.Descriptor instead.
func (ExecutionStatus) EnumDescriptor() ([]byte, []int) {
	return file_runner_proto_runner_proto_rawDescGZIP(), []int{0}
}

type ConfigureRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Config        map[string]string      `protobuf:"bytes,1,rep,name=config,proto3" json:"config,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConfigureRequest) Reset() {
	*x = ConfigureRequest{}
	mi := &file_runner_proto_runner_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConfigureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigureRequest) ProtoMessage() {}

func (x *ConfigureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_runner_proto_runner_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigureRequest.ProtoReflect.Descriptor instead.
func (*ConfigureRequest) Descriptor() ([]byte, []int) {
	return file_runner_proto_runner_proto_rawDescGZIP(), []int{0}
}

func (x *ConfigureRequest) GetConfig() map[string]string {
	if x != nil {
		return x.Config
	}
	return nil
}

type ConfigureResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Value         []byte                 `protobuf:"bytes,1,opt,name=value,proto3" json:"value,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ConfigureResponse) Reset() {
	*x = ConfigureResponse{}
	mi := &file_runner_proto_runner_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ConfigureResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigureResponse) ProtoMessage() {}

func (x *ConfigureResponse) ProtoReflect() protoreflect.Message {
	mi := &file_runner_proto_runner_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigureResponse.ProtoReflect.Descriptor instead.
func (*ConfigureResponse) Descriptor() ([]byte, []int) {
	return file_runner_proto_runner_proto_rawDescGZIP(), []int{1}
}

func (x *ConfigureResponse) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

type EvalRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	BundlePaths   []string               `protobuf:"bytes,1,rep,name=bundlePaths,proto3" json:"bundlePaths,omitempty"`
	ApiServer     uint32                 `protobuf:"varint,2,opt,name=apiServer,proto3" json:"apiServer,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EvalRequest) Reset() {
	*x = EvalRequest{}
	mi := &file_runner_proto_runner_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EvalRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EvalRequest) ProtoMessage() {}

func (x *EvalRequest) ProtoReflect() protoreflect.Message {
	mi := &file_runner_proto_runner_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EvalRequest.ProtoReflect.Descriptor instead.
func (*EvalRequest) Descriptor() ([]byte, []int) {
	return file_runner_proto_runner_proto_rawDescGZIP(), []int{2}
}

func (x *EvalRequest) GetBundlePaths() []string {
	if x != nil {
		return x.BundlePaths
	}
	return nil
}

func (x *EvalRequest) GetApiServer() uint32 {
	if x != nil {
		return x.ApiServer
	}
	return 0
}

// *
// EvalResponse is the result of an assessment check
// Results are sent back by the plugins using the Result service defined
// separately.
type EvalResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Status        ExecutionStatus        `protobuf:"varint,1,opt,name=Status,proto3,enum=proto.ExecutionStatus" json:"Status,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *EvalResponse) Reset() {
	*x = EvalResponse{}
	mi := &file_runner_proto_runner_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EvalResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EvalResponse) ProtoMessage() {}

func (x *EvalResponse) ProtoReflect() protoreflect.Message {
	mi := &file_runner_proto_runner_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EvalResponse.ProtoReflect.Descriptor instead.
func (*EvalResponse) Descriptor() ([]byte, []int) {
	return file_runner_proto_runner_proto_rawDescGZIP(), []int{3}
}

func (x *EvalResponse) GetStatus() ExecutionStatus {
	if x != nil {
		return x.Status
	}
	return ExecutionStatus_SUCCESS
}

var File_runner_proto_runner_proto protoreflect.FileDescriptor

var file_runner_proto_runner_proto_rawDesc = string([]byte{
	0x0a, 0x19, 0x72, 0x75, 0x6e, 0x6e, 0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x72,
	0x75, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x8a, 0x01, 0x0a, 0x10, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x3b, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x1a, 0x39, 0x0a, 0x0b, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22,
	0x29, 0x0a, 0x11, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x22, 0x4d, 0x0a, 0x0b, 0x45, 0x76,
	0x61, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x62, 0x75, 0x6e,
	0x64, 0x6c, 0x65, 0x50, 0x61, 0x74, 0x68, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x0b,
	0x62, 0x75, 0x6e, 0x64, 0x6c, 0x65, 0x50, 0x61, 0x74, 0x68, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x61,
	0x70, 0x69, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09,
	0x61, 0x70, 0x69, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x22, 0x3e, 0x0a, 0x0c, 0x45, 0x76, 0x61,
	0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x2e, 0x0a, 0x06, 0x53, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x2e, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x52, 0x06, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2a, 0x2b, 0x0a, 0x0f, 0x45, 0x78, 0x65,
	0x63, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x0b, 0x0a, 0x07,
	0x53, 0x55, 0x43, 0x43, 0x45, 0x53, 0x53, 0x10, 0x00, 0x12, 0x0b, 0x0a, 0x07, 0x46, 0x41, 0x49,
	0x4c, 0x55, 0x52, 0x45, 0x10, 0x01, 0x32, 0x79, 0x0a, 0x06, 0x52, 0x75, 0x6e, 0x6e, 0x65, 0x72,
	0x12, 0x3e, 0x0a, 0x09, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x12, 0x17, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x18, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x2f, 0x0a, 0x04, 0x45, 0x76, 0x61, 0x6c, 0x12, 0x12, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x45, 0x76, 0x61, 0x6c, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x13, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x45, 0x76, 0x61, 0x6c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x42, 0x09, 0x5a, 0x07, 0x2e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_runner_proto_runner_proto_rawDescOnce sync.Once
	file_runner_proto_runner_proto_rawDescData []byte
)

func file_runner_proto_runner_proto_rawDescGZIP() []byte {
	file_runner_proto_runner_proto_rawDescOnce.Do(func() {
		file_runner_proto_runner_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_runner_proto_runner_proto_rawDesc), len(file_runner_proto_runner_proto_rawDesc)))
	})
	return file_runner_proto_runner_proto_rawDescData
}

var file_runner_proto_runner_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_runner_proto_runner_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_runner_proto_runner_proto_goTypes = []any{
	(ExecutionStatus)(0),      // 0: proto.ExecutionStatus
	(*ConfigureRequest)(nil),  // 1: proto.ConfigureRequest
	(*ConfigureResponse)(nil), // 2: proto.ConfigureResponse
	(*EvalRequest)(nil),       // 3: proto.EvalRequest
	(*EvalResponse)(nil),      // 4: proto.EvalResponse
	nil,                       // 5: proto.ConfigureRequest.ConfigEntry
}
var file_runner_proto_runner_proto_depIdxs = []int32{
	5, // 0: proto.ConfigureRequest.config:type_name -> proto.ConfigureRequest.ConfigEntry
	0, // 1: proto.EvalResponse.Status:type_name -> proto.ExecutionStatus
	1, // 2: proto.Runner.Configure:input_type -> proto.ConfigureRequest
	3, // 3: proto.Runner.Eval:input_type -> proto.EvalRequest
	2, // 4: proto.Runner.Configure:output_type -> proto.ConfigureResponse
	4, // 5: proto.Runner.Eval:output_type -> proto.EvalResponse
	4, // [4:6] is the sub-list for method output_type
	2, // [2:4] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_runner_proto_runner_proto_init() }
func file_runner_proto_runner_proto_init() {
	if File_runner_proto_runner_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_runner_proto_runner_proto_rawDesc), len(file_runner_proto_runner_proto_rawDesc)),
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_runner_proto_runner_proto_goTypes,
		DependencyIndexes: file_runner_proto_runner_proto_depIdxs,
		EnumInfos:         file_runner_proto_runner_proto_enumTypes,
		MessageInfos:      file_runner_proto_runner_proto_msgTypes,
	}.Build()
	File_runner_proto_runner_proto = out.File
	file_runner_proto_runner_proto_goTypes = nil
	file_runner_proto_runner_proto_depIdxs = nil
}
