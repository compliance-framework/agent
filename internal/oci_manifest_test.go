package internal

import (
	"reflect"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestAnnotationsFromDescriptor(t *testing.T) {
	tests := []struct {
		name     string
		desc     *remote.Descriptor
		expected map[string]string
	}{
		{
			name:     "Nil descriptor",
			desc:     nil,
			expected: map[string]string{},
		},
		{
			name: "Invalid JSON falls back to descriptor annotations",
			desc: &remote.Descriptor{
				Manifest: []byte("not-json"),
				Descriptor: v1.Descriptor{
					Annotations: map[string]string{"from": "descriptor"},
				},
			},
			expected: map[string]string{"from": "descriptor"},
		},
		{
			name: "Manifest without annotations falls back to descriptor annotations",
			desc: &remote.Descriptor{
				Manifest: []byte(`{"schemaVersion":2}`),
				Descriptor: v1.Descriptor{
					Annotations: map[string]string{"from": "descriptor"},
				},
			},
			expected: map[string]string{"from": "descriptor"},
		},
		{
			name: "Uses manifest annotations when present",
			desc: &remote.Descriptor{
				Manifest: []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"annotations":{"org.opencontainers.image.created":"2026-02-27T10:57:27Z","org.opencontainers.image.title":"plugin-test","org.opencontainers.image.version":"v0.1.0","org.ccf.plugin.protocol.version":"2"}}`),
				Descriptor: v1.Descriptor{
					Annotations: map[string]string{"from": "descriptor"},
				},
			},
			expected: map[string]string{
				"org.opencontainers.image.created": "2026-02-27T10:57:27Z",
				"org.opencontainers.image.title":   "plugin-test",
				"org.opencontainers.image.version": "v0.1.0",
				"org.ccf.plugin.protocol.version":  "2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := annotationsFromDescriptor(tt.desc)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("annotationsFromDescriptor() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

func TestAnnotationsFromDescriptor_ReturnsDefensiveCopy(t *testing.T) {
	t.Run("Descriptor annotations are copied", func(t *testing.T) {
		desc := &remote.Descriptor{
			Descriptor: v1.Descriptor{
				Annotations: map[string]string{"from": "descriptor"},
			},
		}

		got := annotationsFromDescriptor(desc)
		got["from"] = "modified"

		if desc.Annotations["from"] != "descriptor" {
			t.Fatalf("expected descriptor annotations to remain unchanged, got %q", desc.Annotations["from"])
		}
	})

	t.Run("Manifest annotations are copied", func(t *testing.T) {
		desc := &remote.Descriptor{
			Manifest: []byte(`{"schemaVersion":2,"annotations":{"org.ccf.plugin.protocol.version":"2"}}`),
		}

		got := annotationsFromDescriptor(desc)
		got["org.ccf.plugin.protocol.version"] = "1"

		again := annotationsFromDescriptor(desc)
		if again["org.ccf.plugin.protocol.version"] != "2" {
			t.Fatalf("expected manifest annotations to remain unchanged, got %q", again["org.ccf.plugin.protocol.version"])
		}
	})
}
