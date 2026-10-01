// Package policytree reads policy trees from disk and archives them. It is the one place
// that decides which files a policy tree has, so every consumer sees the same tree: inline
// bundle materialization, the report inventory, and the policy bundle artifacts uploaded at
// configuration time (the reconciler) and at evaluation time (the plugins' API helper).
// Uploading the same directory from either place therefore produces the same bytes, and the
// API assigns the same artifact digest (R62).
//
// The package is a leaf: it imports only the standard library.
package policytree

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// ReadTree reads the regular files under dir, keyed by their slash-separated path relative
// to dir. dir itself may be a symlink (for example /etc/ccf/policies -> a versioned
// directory, or an inline bundle's stable path); symlinks inside the tree are skipped and
// returned, as OPA's bundle loader skips them too. Other non-regular files are ignored.
func ReadTree(dir string) (files map[string][]byte, skipped []string, err error) {
	files = map[string][]byte{}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, nil, err
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.Type()&fs.ModeSymlink != 0 {
			skipped = append(skipped, rel)
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[rel] = raw
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return files, skipped, nil
}

// TarFiles archives files as regular entries in path order, with a fixed mode and no
// times, so the same file map always produces the same bytes. (The API canonicalizes the
// archive anyway; determinism here makes the local upload cache hit.)
func TarFiles(files map[string][]byte) ([]byte, error) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, p := range paths {
		content := files[p]
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: p, Mode: 0o644, Size: int64(len(content))}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(content); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// TarDirectory is ReadTree followed by TarFiles.
func TarDirectory(dir string) ([]byte, error) {
	files, _, err := ReadTree(dir)
	if err != nil {
		return nil, err
	}
	return TarFiles(files)
}
