package inlinepolicy

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/hashicorp/go-hclog"
)

// testLayout is the layout of the tests: the trees under root/store and the stable links
// under root/links.
func testLayout(root string) Layout {
	return Layout{Store: filepath.Join(root, "store"), Links: filepath.Join(root, "links")}
}

func skipWithoutSymlinks(t *testing.T, root string) {
	t.Helper()
	if runtime.GOOS == "windows" || !symlinksSupported(root) {
		t.Skip("symlinks are not available")
	}
}

const stablePkg = "package compliance_framework.stable\n\ntitle := \"stable\"\n\nviolation contains {\"id\": \"s\"} if input.bad\n"

// evidenceOf evaluates the policy path the way a plugin does and returns, per package, the
// evidence UUID and the policy file policy-manager seeds it with.
func evidenceOf(t *testing.T, policyPath string) map[string][2]string {
	t.Helper()
	pm := policyManager.New(context.Background(), hclog.NewNullLogger(), policyPath, nil)
	results, err := pm.Execute(context.Background(), map[string]any{"bad": true})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := policyManager.NewPolicyProcessor(hclog.NewNullLogger(), map[string]string{"plugin": "ssh"}, nil, nil, nil, nil, nil, nil).
		GenerateResults(context.Background(), policyPath, map[string]any{"bad": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(evidence) != len(results) {
		t.Fatalf("expected one evidence per result: %d vs %d", len(evidence), len(results))
	}
	out := map[string][2]string{}
	for _, r := range results {
		pkg := r.Policy.Package.PurePackage()
		for _, e := range evidence {
			if e.Labels["_policy"] == pkg {
				out[pkg] = [2]string{e.UUID, r.Policy.File}
			}
		}
	}
	return out
}

// TestActivate_EvidenceIdentityIsStable_R67: two inline revisions that only change another
// package give the unchanged package the same policy_file, so the same evidence UUID.
func TestActivate_EvidenceIdentityIsStable_R67(t *testing.T) {
	root := t.TempDir()
	skipWithoutSymlinks(t, root)
	revision := func(other string) *Materialized {
		m, err := Materialize(context.Background(), testLayout(root), "ssh", &agentconfig.PolicyBundle{Modules: map[string]string{
			"stable.rego": stablePkg,
			"other.rego":  "package compliance_framework.other\n\ntitle := \"" + other + "\"\n",
		}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := Activate(testLayout(root), "ssh", m.Dir); err != nil {
			t.Fatal(err)
		}
		return m
	}

	first := revision("v1")
	before := evidenceOf(t, first.Path)
	second := revision("v2")
	after := evidenceOf(t, second.Path)

	if first.Dir == second.Dir || first.Path != second.Path {
		t.Fatalf("the trees must differ and the stable path must not: %s %s / %s %s", first.Dir, second.Dir, first.Path, second.Path)
	}
	if want := filepath.Join(root, "links", "ssh", "policies"); first.Path != want {
		t.Fatalf("stable path = %s, want %s", first.Path, want)
	}
	const stable, other = "compliance_framework.stable", "compliance_framework.other"
	if before[stable] != after[stable] || before[stable][0] == "" {
		t.Fatalf("an unchanged package must keep its evidence UUID and policy_file: %v vs %v", before[stable], after[stable])
	}
	if before[other][1] != after[other][1] || after[other][0] == "" {
		t.Fatalf("policy_file must not depend on the revision: %v vs %v", before[other], after[other])
	}

	// The stable path resolves to the active tree, so an artifact upload of it is the tree.
	resolved, err := filepath.EvalSymlinks(second.Path)
	if err != nil {
		t.Fatal(err)
	}
	wantDir, _ := filepath.EvalSymlinks(second.Dir)
	if resolved != wantDir {
		t.Fatalf("stable path resolves to %s, want %s", resolved, wantDir)
	}
}

func TestActivate_RejectsForeignDirs(t *testing.T) {
	root := t.TempDir()
	skipWithoutSymlinks(t, root)
	store := testLayout(root).Store
	for _, dir := range []string{t.TempDir(), filepath.Join(store, "other", "abc", "policies"), filepath.Join(store, "ssh", "abc"), filepath.Join(store, "ssh", "abc", "bundle")} {
		if err := Activate(testLayout(root), "ssh", dir); err == nil {
			t.Fatalf("activating %s must fail", dir)
		}
	}
	if err := Activate(testLayout(root), "ssh", filepath.Join(store, "ssh", "abc", "policies")); err == nil {
		t.Fatal("activating a missing tree must fail")
	}
}

// TestGC_NeverRemovesCurrent: the tree current points to survives GC even when nothing keeps
// it and it is the oldest.
func TestGC_NeverRemovesCurrent(t *testing.T) {
	root := t.TempDir()
	skipWithoutSymlinks(t, root)
	var dirs []string
	for _, title := range []string{"a", "b", "c"} {
		m, err := Materialize(context.Background(), testLayout(root), "ssh", &agentconfig.PolicyBundle{Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"" + title + "\"\n",
		}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		dirs = append(dirs, m.Dir)
	}
	if err := Activate(testLayout(root), "ssh", dirs[0]); err != nil {
		t.Fatal(err)
	}
	// A crash between creating and renaming the temporary link leaves it behind.
	stale := filepath.Join(root, "links", tmpPrefix+"ssh-stale")
	if err := os.Symlink("x", stale); err != nil {
		t.Fatal(err)
	}
	if err := GC(testLayout(root), nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dirs[0]); err != nil {
		t.Fatalf("the active tree was removed: %v", err)
	}
	for _, d := range dirs[1:] {
		if _, err := os.Stat(filepath.Dir(d)); !os.IsNotExist(err) {
			t.Fatalf("%s should have been collected", d)
		}
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatal("a stale temporary link must be removed")
	}
	if _, err := os.Stat(filepath.Join(root, "links", "ssh", "policies", "x.rego")); err != nil {
		t.Fatalf("the stable path must still resolve: %v", err)
	}
}

// TestActivate_SwapIsAtomic: on Linux, readers resolving the stable path while it is swapped
// always find one of the two trees, never a missing path. (A reader walking the tree across a
// swap can still mix files of both trees, and on macOS APFS a lookup racing the rename can
// fail with EINVAL; the agent therefore swaps only between configuration runs, never while a
// plugin of the previous configuration runs.)
func TestActivate_SwapIsAtomic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("rename(2) over a symlink is atomic for concurrent lookups on Linux only")
	}
	root := t.TempDir()
	skipWithoutSymlinks(t, root)
	var trees [2]*Materialized
	for i, title := range []string{"a", "b"} {
		m, err := Materialize(context.Background(), testLayout(root), "ssh", &agentconfig.PolicyBundle{Modules: map[string]string{
			"x.rego": "package compliance_framework.x\n\ntitle := \"" + title + "\"\n",
		}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		trees[i] = m
	}
	if err := Activate(testLayout(root), "ssh", trees[0].Dir); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, m := range trees {
		resolved, err := filepath.EvalSymlinks(m.Dir)
		if err != nil {
			t.Fatal(err)
		}
		want[resolved] = true
	}

	var stop atomic.Bool
	var failures atomic.Int32
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				resolved, err := filepath.EvalSymlinks(trees[0].Path)
				if err != nil || !want[resolved] {
					failures.Add(1)
				}
				if _, err := os.ReadFile(filepath.Join(trees[0].Path, "x.rego")); err != nil {
					failures.Add(1)
				}
			}
		}()
	}
	for i := range 500 {
		if err := Activate(testLayout(root), "ssh", trees[(i+1)%2].Dir); err != nil {
			t.Error(err)
			break
		}
	}
	stop.Store(true)
	wg.Wait()
	if n := failures.Load(); n != 0 {
		t.Fatalf("%d reads did not find a complete tree during the swaps", n)
	}
}
