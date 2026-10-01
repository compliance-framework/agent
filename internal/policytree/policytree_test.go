package policytree

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
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
