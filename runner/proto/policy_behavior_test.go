package proto

import (
	"reflect"
	"testing"
)

func TestEvalRequestWithUndefinedMappedTo(t *testing.T) {
	t.Run("nil request returns nil", func(t *testing.T) {
		var request *EvalRequest
		if got := request.WithUndefinedMappedTo([]string{"vpc"}); got != nil {
			t.Fatalf("WithUndefinedMappedTo() = %#v, want nil", got)
		}
	})

	t.Run("adds full path mapping for uncovered policies", func(t *testing.T) {
		request := &EvalRequest{
			PolicyPaths: []string{"/tmp/unmapped/vpc.rego"},
		}

		got := request.WithUndefinedMappedTo([]string{"vpc"})

		wantBehavior := map[string]*StringList{
			"/tmp/unmapped/vpc.rego": {Values: []string{"vpc"}},
		}
		if !reflect.DeepEqual(got.PolicyBehavior, wantBehavior) {
			t.Fatalf("WithUndefinedMappedTo().PolicyBehavior = %#v, want %#v", got.PolicyBehavior, wantBehavior)
		}

		if request.PolicyBehavior != nil {
			t.Fatalf("original request.PolicyBehavior = %#v, want nil", request.PolicyBehavior)
		}
	})

	t.Run("does not add full path mapping for covered policies", func(t *testing.T) {
		request := &EvalRequest{
			PolicyPaths: []string{"/tmp/plugin-aws-networking-security-policies/vpc.rego"},
			PolicyBehavior: map[string]*StringList{
				"plugin-aws-networking-security-policies": {Values: []string{"vpc"}},
			},
		}

		got := request.WithUndefinedMappedTo([]string{"vpc"})

		wantBehavior := map[string]*StringList{
			"plugin-aws-networking-security-policies": {Values: []string{"vpc"}},
		}
		if !reflect.DeepEqual(got.PolicyBehavior, wantBehavior) {
			t.Fatalf("WithUndefinedMappedTo().PolicyBehavior = %#v, want %#v", got.PolicyBehavior, wantBehavior)
		}
	})

	t.Run("chains after defaults and fills only remaining uncovered paths", func(t *testing.T) {
		request := &EvalRequest{
			PolicyPaths: []string{
				"/tmp/plugin-aws-networking-security-policies/vpc.rego",
				"/tmp/custom/unmapped.rego",
			},
		}

		got := request.
			WithDefaultPolicyBehavior(map[string][]string{
				"plugin-aws-networking-security-policies": {"vpc"},
			}).
			WithUndefinedMappedTo([]string{"vpc"}).
			PolicyPathsForBehavior("vpc")

		want := []string{
			"/tmp/plugin-aws-networking-security-policies/vpc.rego",
			"/tmp/custom/unmapped.rego",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("defaults then undefined chain result = %#v, want %#v", got, want)
		}
	})
}

func TestEvalRequestWithDefaultPolicyBehavior(t *testing.T) {
	t.Run("nil request returns nil", func(t *testing.T) {
		var request *EvalRequest
		if got := request.WithDefaultPolicyBehavior(map[string][]string{"default": {"vpc"}}); got != nil {
			t.Fatalf("WithDefaultPolicyBehavior() = %#v, want nil", got)
		}
	})

	t.Run("returns copied request with defaults when config is empty", func(t *testing.T) {
		request := &EvalRequest{
			PolicyPaths: []string{"/tmp/default-policies/vpc.rego"},
		}

		got := request.WithDefaultPolicyBehavior(map[string][]string{
			"default-policies": {"vpc"},
		})

		want := &EvalRequest{
			PolicyPaths: []string{"/tmp/default-policies/vpc.rego"},
			PolicyBehavior: map[string]*StringList{
				"default-policies": {Values: []string{"vpc"}},
			},
		}

		if !reflect.DeepEqual(got, want) {
			t.Fatalf("WithDefaultPolicyBehavior() = %#v, want %#v", got, want)
		}

		if request.PolicyBehavior != nil {
			t.Fatalf("original request.PolicyBehavior = %#v, want nil", request.PolicyBehavior)
		}
	})

	t.Run("configured values take precedence over defaults", func(t *testing.T) {
		request := &EvalRequest{
			PolicyPaths: []string{
				"/tmp/default-policies/vpc.rego",
				"/tmp/configured-policies/subnet.rego",
			},
			PolicyBehavior: map[string]*StringList{
				"default-policies":    {Values: []string{"subnet"}},
				"configured-policies": {Values: []string{"subnet"}},
			},
		}

		got := request.WithDefaultPolicyBehavior(map[string][]string{
			"default-policies": {"vpc"},
			"extra-policies":   {"vpc"},
		})

		wantBehavior := map[string]*StringList{
			"default-policies":    {Values: []string{"subnet"}},
			"configured-policies": {Values: []string{"subnet"}},
			"extra-policies":      {Values: []string{"vpc"}},
		}

		if !reflect.DeepEqual(got.PolicyBehavior, wantBehavior) {
			t.Fatalf("WithDefaultPolicyBehavior().PolicyBehavior = %#v, want %#v", got.PolicyBehavior, wantBehavior)
		}

		if !reflect.DeepEqual(request.PolicyBehavior["default-policies"].Values, []string{"subnet"}) {
			t.Fatalf("original configured values were mutated: %#v", request.PolicyBehavior["default-policies"].Values)
		}
	})

	t.Run("chains into PolicyPathsForBehavior", func(t *testing.T) {
		request := &EvalRequest{
			PolicyPaths: []string{"/tmp/default-policies/vpc.rego", "/tmp/other-policies/general.rego"},
		}

		got := request.WithDefaultPolicyBehavior(map[string][]string{
			"default-policies": {"vpc"},
		}).PolicyPathsForBehavior("vpc")

		want := []string{"/tmp/default-policies/vpc.rego"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("WithDefaultPolicyBehavior(...).PolicyPathsForBehavior() = %#v, want %#v", got, want)
		}
	})
}

func TestEvalRequestPolicyPathsForBehavior(t *testing.T) {
	tests := []struct {
		name     string
		request  *EvalRequest
		behavior string
		want     []string
	}{
		{
			name:     "nil request returns nil",
			request:  nil,
			behavior: "vpc",
			want:     nil,
		},
		{
			name: "no policy behavior returns empty list",
			request: &EvalRequest{
				PolicyPaths: []string{"/tmp/a", "/tmp/b"},
			},
			behavior: "vpc",
			want:     []string{},
		},
		{
			name: "matching behavior filters paths by matching keys",
			request: &EvalRequest{
				PolicyPaths: []string{
					"/tmp/plugin-aws-networking-security-policies/vpc.rego",
					"/tmp/other-policies/general.rego",
				},
				PolicyBehavior: map[string]*StringList{
					"plugin-aws-networking-security-policies": {Values: []string{"vpc"}},
					"other-policies": {Values: []string{"subnet"}},
				},
			},
			behavior: "vpc",
			want:     []string{"/tmp/plugin-aws-networking-security-policies/vpc.rego"},
		},
		{
			name: "no matching behavior returns empty list",
			request: &EvalRequest{
				PolicyPaths: []string{"/tmp/a", "/tmp/b"},
				PolicyBehavior: map[string]*StringList{
					"plugin-aws-networking-security-policies": {Values: []string{"vpc"}},
				},
			},
			behavior: "subnet",
			want:     []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.request.PolicyPathsForBehavior(test.behavior)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("PolicyPathsForBehavior() = %#v, want %#v", got, test.want)
			}
		})
	}
}
