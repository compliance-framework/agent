// Package inlinepolicy materializes inline policy bundles (policy_bundles in the file or the
// remote overlay) into write-once directories that plugins load like any other policy path,
// and checks them the way plugins will evaluate them (HLD §3.5, R17–R21).
//
// The package is a leaf: it imports api/pkg/agentconfig, api/pkg/agentconfig/regocheck,
// api/pkg/policyeval, OPA v1 and the standard library, never cmd.
package inlinepolicy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/compliance-framework/api/pkg/agentconfig"
	"github.com/open-policy-agent/opa/v1/ast"
	"sigs.k8s.io/yaml"
)

// Resolver returns the policy root directory of an OCI tag or a local path (the directory
// plugins would receive for it).
type Resolver func(ctx context.Context, source string) (dir string, err error)

// ErrResolve wraps a failure to fetch a bundle's extends tree (reported as download-failed).
var ErrResolve = errors.New("resolve extends")

// PolicyErrors is a list of policy problems with at least one error; Materialize returns it
// for bundle content problems (reported as rejected/policy-errors).
type PolicyErrors []agentconfig.PolicyError

func (p PolicyErrors) Error() string {
	parts := make([]string, 0, len(p))
	for _, e := range p {
		loc := e.Path
		if e.Row > 0 {
			loc = fmt.Sprintf("%s:%d:%d", e.Path, e.Row, e.Col)
		}
		parts = append(parts, fmt.Sprintf("%s %s: %s", e.Bundle, loc, e.Message))
	}
	return strings.Join(parts, "; ")
}

// Materialized is one bundle written to disk.
type Materialized struct {
	Name   string
	Dir    string // <root>/<name>/<tree digest hex>
	Digest string // agentconfig.BundleTreeDigest(files)
	// Extends describes the vendor tree the bundle extends (nil when standalone).
	Extends *agentconfig.PolicyBundleExtendsReport
	Files   []agentconfig.PolicyFileReport
	// Authored are the paths written from Modules (and data.json when Data is set).
	Authored      map[string]bool
	AuthoredTests []string
	Warnings      []agentconfig.PolicyError // delete of a missing path, skipped symlink, stray data file
}

// Materialize builds bundle name in the R17 order (extends tree, delete, modules, data),
// checks the data-file rule (R18) and writes the result write-once under root.
func Materialize(ctx context.Context, root, name string, b *agentconfig.PolicyBundle, resolve Resolver) (*Materialized, error) {
	if b == nil {
		return nil, PolicyErrors{{Bundle: name, Message: "bundle has no definition", Severity: agentconfig.SeverityError}}
	}
	if !agentconfig.BundleNamePattern.MatchString(name) {
		return nil, PolicyErrors{{Bundle: name, Message: "invalid bundle name", Severity: agentconfig.SeverityError}}
	}
	m := &Materialized{Name: name, Authored: map[string]bool{}}
	var errs PolicyErrors
	warn := func(p, format string, args ...any) {
		m.Warnings = append(m.Warnings, agentconfig.PolicyError{Bundle: name, Path: p, Message: fmt.Sprintf(format, args...), Severity: agentconfig.SeverityWarning})
	}
	fail := func(p, format string, args ...any) {
		errs = append(errs, agentconfig.PolicyError{Bundle: name, Path: p, Message: fmt.Sprintf(format, args...), Severity: agentconfig.SeverityError})
	}

	// 1. Base tree.
	files := map[string][]byte{}
	if b.Extends != nil {
		if resolve == nil {
			return nil, fmt.Errorf("%w: no resolver", ErrResolve)
		}
		dir, err := resolve(ctx, *b.Extends)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %v", ErrResolve, *b.Extends, err)
		}
		baseFiles, skipped, err := readTree(dir)
		if err != nil {
			return nil, fmt.Errorf("%w %s: %v", ErrResolve, *b.Extends, err)
		}
		if !slices.ContainsFunc(sortedKeys(baseFiles), func(p string) bool { return strings.HasSuffix(p, ".rego") }) {
			// An empty or unreadable vendor tree would silently drop every vendor policy.
			return nil, fmt.Errorf("%w %s: the policy tree at %s has no .rego files", ErrResolve, *b.Extends, dir)
		}
		for _, s := range skipped {
			warn(s, "symlink in the extends tree skipped")
		}
		m.Extends = &agentconfig.PolicyBundleExtendsReport{
			Source: *b.Extends,
			Digest: agentconfig.BundleTreeDigest(baseFiles),
			Files:  inventory(baseFiles),
		}
		files = baseFiles
	}

	// 2. Delete.
	for _, p := range b.Delete {
		if err := agentconfig.ValidateModulePath(p); err != nil {
			fail(p, "%s", err.Error())
			continue
		}
		if _, ok := files[p]; !ok {
			warn(p, "delete: %s is not in the extends tree", p)
			continue
		}
		delete(files, p)
	}

	// 3. Modules.
	for _, p := range sortedKeys(b.Modules) {
		if err := checkRelPath(p); err != nil {
			fail(p, "%s", err.Error())
			continue
		}
		files[p] = []byte(b.Modules[p])
		m.Authored[p] = true
		if strings.HasSuffix(p, "_test.rego") {
			m.AuthoredTests = append(m.AuthoredTests, p)
		}
	}

	// 4. Data: RFC 7396 merge patch onto the root data file, emitted as data.json.
	if b.Data != nil {
		for _, f := range agentconfig.DataFileNames {
			if _, ok := b.Modules[f]; ok {
				fail(f, "set either data or a root-level %s module, not both", f)
			}
		}
	}
	if b.Data != nil && len(errs) == 0 {
		if err := mergeRootData(files, b.Data); err != nil {
			fail("data.json", "%s", err.Error())
		} else {
			m.Authored["data.json"] = true
		}
	}

	// 5. Data-name rule (R18): OPA only loads data.json/.yaml/.yml; any other data-like file is
	// an error when authored and a warning when the vendor shipped it.
	for _, p := range sortedKeys(files) {
		ext := strings.ToLower(path.Ext(p))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			continue
		}
		if slices.Contains(agentconfig.DataFileNames, path.Base(p)) {
			continue
		}
		if m.Authored[p] {
			fail(p, "only data.json, data.yaml or data.yml data files are loaded by OPA")
		} else {
			warn(p, "OPA ignores %s: only data.json, data.yaml or data.yml data files are loaded", p)
		}
	}
	if len(errs) > 0 {
		agentconfig.SortPolicyErrors(errs)
		return nil, errs
	}

	// 6. Write once.
	m.Digest = agentconfig.BundleTreeDigest(files)
	final := filepath.Join(root, name, strings.TrimPrefix(m.Digest, agentconfig.TreeDigestPrefix))
	if err := writeOnce(final, files); err != nil {
		return nil, err
	}
	m.Dir = final

	// 7. Inventory.
	m.Files = inventory(files)
	slices.Sort(m.AuthoredTests)
	return m, nil
}

// checkRelPath applies ValidateModulePath and re-checks that the cleaned path stays under the
// policy root.
func checkRelPath(p string) error {
	if err := agentconfig.ValidateModulePath(p); err != nil {
		return err
	}
	clean := filepath.Clean(filepath.FromSlash(p))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("module path %q escapes the policy root", p)
	}
	return nil
}

// mergeRootData merge-patches data onto the root data file (data.json, else a converted
// data.yaml/data.yml) and writes the result as data.json, removing the YAML files.
func mergeRootData(files map[string][]byte, data map[string]any) error {
	target := []byte("{}")
	for _, name := range []string{"data.yaml", "data.yml"} {
		if raw, ok := files[name]; ok {
			converted, err := yaml.YAMLToJSON(raw)
			if err != nil {
				return fmt.Errorf("%s does not parse: %v", name, err)
			}
			merged, err := agentconfig.MergePatch(target, converted)
			if err != nil {
				return err
			}
			target = merged
			delete(files, name)
		}
	}
	if raw, ok := files["data.json"]; ok {
		merged, err := agentconfig.MergePatch(target, raw)
		if err != nil {
			return fmt.Errorf("data.json does not parse: %v", err)
		}
		target = merged
	}
	patch, err := json.Marshal(data)
	if err != nil {
		return err
	}
	out, err := agentconfig.MergePatch(target, patch)
	if err != nil {
		return err
	}
	files["data.json"] = out
	return nil
}

// readTree reads the regular files under dir (paths relative, slash-separated). dir itself
// may be a symlink (e.g. /etc/ccf/policies -> a versioned directory); symlinks inside the
// tree are skipped and returned.
func readTree(dir string) (map[string][]byte, []string, error) {
	files := map[string][]byte{}
	var skipped []string
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, nil, err
	}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
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
	return files, skipped, err
}

// Inventory digests and lists a policy directory (OCI or local sources) for the report.
func Inventory(dir string) (string, []agentconfig.PolicyFileReport, error) {
	files, _, err := readTree(dir)
	if err != nil {
		return "", nil, err
	}
	return agentconfig.BundleTreeDigest(files), inventory(files), nil
}

func inventory(files map[string][]byte) []agentconfig.PolicyFileReport {
	out := make([]agentconfig.PolicyFileReport, 0, len(files))
	for _, p := range sortedKeys(files) {
		sum := sha256.Sum256(files[p])
		r := agentconfig.PolicyFileReport{Path: p, SHA256: hex.EncodeToString(sum[:])}
		if strings.HasSuffix(p, ".rego") {
			if mod, err := ast.ParseModuleWithOpts(p, string(files[p]), ast.ParserOptions{RegoVersion: ast.RegoV1}); err == nil && mod != nil && mod.Package != nil {
				r.Package = strings.TrimPrefix(mod.Package.Path.String(), "data.")
			}
		}
		out = append(out, r)
	}
	return out
}

// writeOnce writes files into final unless it already exists: a temp dir (dirs 0755, files
// 0644) renamed into place. Losing a rename race reuses the winner's directory.
func writeOnce(final string, files map[string][]byte) error {
	if info, err := os.Stat(final); err == nil && info.IsDir() {
		return nil
	}
	parent := filepath.Dir(final)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(parent, ".tmp-"+hex.EncodeToString(rnd[:]))
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	for p, content := range files {
		dst := filepath.Join(tmp, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			cleanup()
			return err
		}
		if err := os.WriteFile(dst, content, 0o644); err != nil {
			cleanup()
			return err
		}
	}
	if err := os.Rename(tmp, final); err != nil {
		cleanup()
		if info, statErr := os.Stat(final); statErr == nil && info.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

// GC removes materialized directories under root except those in keep and the perBundle
// newest per bundle, plus abandoned temp directories.
func GC(root string, keep map[string]struct{}, perBundle int) error {
	bundles, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, b := range bundles {
		if !b.IsDir() {
			continue
		}
		bundleDir := filepath.Join(root, b.Name())
		entries, err := os.ReadDir(bundleDir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		type dirInfo struct {
			path string
			mod  int64
		}
		var dirs []dirInfo
		for _, e := range entries {
			p := filepath.Join(bundleDir, e.Name())
			if strings.HasPrefix(e.Name(), ".tmp-") {
				errs = append(errs, os.RemoveAll(p))
				continue
			}
			if !e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			dirs = append(dirs, dirInfo{p, info.ModTime().UnixNano()})
		}
		sort.Slice(dirs, func(i, j int) bool { return dirs[i].mod > dirs[j].mod })
		kept := 0
		for _, d := range dirs {
			if _, ok := keep[d.path]; ok {
				continue
			}
			if kept < perBundle {
				kept++
				continue
			}
			errs = append(errs, os.RemoveAll(d.path))
		}
	}
	return errors.Join(errs...)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
