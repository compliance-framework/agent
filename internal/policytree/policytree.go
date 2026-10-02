// Package policytree reads policy trees from disk, inventories them and archives them. It is
// the one place that decides which files a policy tree has, so every consumer sees the same
// tree: the report inventory, and the policy bundle artifacts uploaded at configuration time
// (the reconciler) and at evaluation time (the plugins' API helper). Uploading the same
// directory from either place therefore produces the same bytes, and the API assigns the
// same artifact digest (R62).
package policytree

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/open-policy-agent/opa/v1/ast"
)

// ReadTree reads the regular files under dir, keyed by their slash-separated path relative
// to dir. dir itself may be a symlink (for example /etc/ccf/policies -> a versioned
// directory); symlinks inside the tree are skipped and
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

// Inventory digests and lists the policy tree at dir (an OCI or local policy source) for the
// config report: the tree digest (agentconfig.BundleTreeDigest) and every file with its
// SHA-256 and, for a Rego module, its package.
func Inventory(dir string) (string, []agentconfig.PolicyFileReport, error) {
	files, _, err := ReadTree(dir)
	if err != nil {
		return "", nil, err
	}
	return agentconfig.BundleTreeDigest(files), inventory(files), nil
}

func inventory(files map[string][]byte) []agentconfig.PolicyFileReport {
	out := make([]agentconfig.PolicyFileReport, 0, len(files))
	for _, p := range slices.Sorted(maps.Keys(files)) {
		sum := sha256.Sum256(files[p])
		r := agentconfig.PolicyFileReport{Path: p, SHA256: hex.EncodeToString(sum[:])}
		if strings.HasSuffix(p, ".rego") {
			r.Package = packageOf(p, files[p])
		}
		out = append(out, r)
	}
	return out
}

// packageOf returns the package of a Rego module without the leading "data.", parsing it as
// Rego v1, then as Rego v0, as plugins on either OPA major would load it. It is "" when the
// module does not parse.
func packageOf(p string, src []byte) string {
	for _, v := range []ast.RegoVersion{ast.RegoV1, ast.RegoV0} {
		mod, err := ast.ParseModuleWithOpts(p, string(src), ast.ParserOptions{RegoVersion: v})
		if err == nil && mod != nil && mod.Package != nil {
			return strings.TrimPrefix(mod.Package.Path.String(), "data.")
		}
	}
	return ""
}
