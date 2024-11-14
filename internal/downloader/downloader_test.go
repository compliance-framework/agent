package downloader

import (
	"testing"
)

func Test_isOci(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected bool
	}{
		{
			name:     "Basic OCI prefixed url",
			source:   "oci://docker.io/library/alpine",
			expected: true,
		},
		{
			name:     "Basic OCI prefixed url with version",
			source:   "oci://docker.io/library/alpine:1.0",
			expected: true,
		},
		{
			name:     "Basic OCI url",
			source:   "docker.io/library/alpine",
			expected: true,
		},
		{
			name:     "Basic OCI url with protocol",
			source:   "https://docker.io/library/alpine",
			expected: true,
		},
		{
			name:     "Basic OCI url with version",
			source:   "docker.io/library/alpine:1.0",
			expected: true,
		},
		{
			name:     "Basic OCI url with latest tag",
			source:   "docker.io/library/alpine:latest",
			expected: true,
		},
		{
			name:     "Tar artifact",
			source:   "docker.io/library/alpine.tar.gz",
			expected: false,
		},
		{
			name:     "Tar artifact with https",
			source:   "https://docker.io/library/alpine.tar.gz",
			expected: false,
		},
		{
			name:     "Zip artifact",
			source:   "docker.io/library/alpine.zip",
			expected: false,
		},
		{
			name:     "Zip artifact with https",
			source:   "https://docker.io/library/alpine.zip",
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isOci(tt.source); got != tt.expected {
				t.Errorf("isOciPlugin() = %v, want %v", got, tt.expected)
			}
		})
	}
}
