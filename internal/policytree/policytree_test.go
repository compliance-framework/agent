package policytree

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/compliance-framework/api/pkg/agentconfig"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestReadTree_FollowsRootSymlinkSkipsInner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	tree := filepath.Join(base, "v2")
	write(t, filepath.Join(tree, "a.rego"), "a")
	write(t, filepath.Join(tree, "sub", "b.rego"), "b")
	write(t, filepath.Join(base, "outside.rego"), "secret")
	if err := os.Symlink(filepath.Join(base, "outside.rego"), filepath.Join(tree, "link.rego")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("v2", filepath.Join(base, "current")); err != nil {
		t.Fatal(err)
	}

	files, skipped, err := ReadTree(filepath.Join(base, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || string(files["a.rego"]) != "a" || string(files["sub/b.rego"]) != "b" {
		t.Fatalf("files = %v", files)
	}
	if len(skipped) != 1 || skipped[0] != "link.rego" {
		t.Fatalf("skipped = %v", skipped)
	}

	// The symlinked root and the directory itself archive to the same bytes.
	viaLink, err := TarDirectory(filepath.Join(base, "current"))
	if err != nil {
		t.Fatal(err)
	}
	direct, err := TarDirectory(tree)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(viaLink, direct) {
		t.Fatal("a symlinked root must archive like the directory it points to")
	}
}

func TestTarFiles_DeterministicAndSorted(t *testing.T) {
	files := map[string][]byte{"z.rego": []byte("z"), "a/b.rego": []byte("b"), "m.json": []byte("{}")}
	first, err := TarFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		again, err := TarFiles(map[string][]byte{"m.json": []byte("{}"), "z.rego": []byte("z"), "a/b.rego": []byte("b")})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("the same file map must archive to the same bytes")
		}
	}
	tr := tar.NewReader(bytes.NewReader(first))
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg || h.Mode != 0o644 || !h.ModTime.IsZero() && h.ModTime.Unix() != 0 {
			t.Fatalf("unexpected header %+v", h)
		}
		names = append(names, h.Name)
	}
	if len(names) != 3 || names[0] != "a/b.rego" || names[1] != "m.json" || names[2] != "z.rego" {
		t.Fatalf("entries = %v", names)
	}
}

func TestInventory(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "banner.rego"), "package compliance_framework.banner\n\nviolation contains {\"id\": \"b\"} if not input.banner\n")
	write(t, filepath.Join(dir, "legacy", "v0.rego"), "package compliance_framework.legacy\n\nviolation[{\"id\": \"l\"}] { input.bad }\n")
	write(t, filepath.Join(dir, "broken.rego"), "package\n")
	write(t, filepath.Join(dir, "data.json"), "{}")

	digest, files, err := Inventory(dir)
	if err != nil {
		t.Fatal(err)
	}
	tree, _, err := ReadTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := agentconfig.BundleTreeDigest(tree); digest != want {
		t.Fatalf("digest = %q, want the tree digest %q", digest, want)
	}
	want := map[string]string{
		"banner.rego":    "compliance_framework.banner",
		"broken.rego":    "",
		"data.json":      "",
		"legacy/v0.rego": "compliance_framework.legacy",
	}
	if len(files) != len(want) {
		t.Fatalf("files = %+v", files)
	}
	for i, f := range files {
		if i > 0 && files[i-1].Path >= f.Path {
			t.Fatalf("files must be sorted by path: %+v", files)
		}
		pkg, ok := want[f.Path]
		if !ok || f.Package != pkg {
			t.Fatalf("file %s: package %q, want %q (known %v)", f.Path, f.Package, pkg, ok)
		}
		sum := sha256.Sum256(tree[f.Path])
		if f.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("file %s: sha256 %s", f.Path, f.SHA256)
		}
	}

	if _, _, err := Inventory(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing tree must be an error")
	}
}
