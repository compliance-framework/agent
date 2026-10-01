// Package inlinepolicy materializes inline policy bundles (policy_bundles in the file or the
// remote overlay) into write-once directories that plugins load like any other policy path,
// and checks them the way plugins will evaluate them (HLD §3.5, R17–R21).
//
// It imports api/pkg/agentconfig, api/pkg/policyeval, internal/policytree, policy-manager
// (to dry-run bundles through the exact calls plugins make), OPA v1 and the standard
// library, never cmd.
package inlinepolicy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/compliance-framework/agent/internal/policytree"
	"github.com/compliance-framework/agent/internal/policyview"
	"github.com/compliance-framework/api/pkg/agentconfig"
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

// Layout is where inline bundles live on disk (R67, R82):
//
//	<Store>/<name>/<tree digest hex>/policies/...   the tree, write-once and content-addressed (Dir)
//	<Links>/<name> -> <Store>/<name>/<tree digest hex>   swapped atomically by Activate
//
// Plugins receive Path, <Links>/<name>/policies: the same path for every revision of the
// bundle, so the policy_file of an unchanged package, and with it the evidence UUID that
// policy-manager seeds with it, survives edits of other files. The agent uses the relative
// Links .compliance-framework/policies/inline, next to the OCI policy cache, so an inline
// bundle's path reads like a local source's and does not depend on the state directory
// (R82). The symlink is an intermediate path component on purpose: OPA's bundle loader does
// not descend into a symlinked root directory, but resolves a symlink earlier in the path
// like any other, so policies/ is a real directory inside the tree.
//
// Two agents that share a working directory and use the same bundle name share
// <Links>/<name> and would swap it under each other; run one agent per working directory.
type Layout struct {
	// Store holds the content-addressed trees (under the agent's state directory).
	Store string
	// Links holds each bundle's stable symlink. Plugins receive paths under it.
	Links string
}

// Materialized is one bundle written to disk (see Layout).
type Materialized struct {
	Name string
	// Dir is the tree itself (<Store>/<name>/<hex>/policies). The checks run on it and its
	// contents never change.
	Dir string
	// Path is what plugins receive: <Links>/<name>/policies, or Dir when the file system has
	// no symlinks (then evidence identity changes with each revision, as before R67).
	Path   string
	Digest string // agentconfig.BundleTreeDigest(files)
	// Extends describes the vendor tree the bundle extends (nil when standalone).
	Extends *agentconfig.PolicyBundleExtendsReport
	// ExtendsDir is the directory the extends tree was read from.
	ExtendsDir string
	Files      []agentconfig.PolicyFileReport
	// Authored are the paths written from Modules (and data.json when Data is set).
	Authored      map[string]bool
	AuthoredTests []string
	Warnings      []agentconfig.PolicyError // delete of a missing path, skipped symlink, stray data file

	// Identities are the evidence identities of the tree's policy modules, and
	// ExtendsIdentities those of the extends tree (R75).
	Identities, ExtendsIdentities []ModuleIdentity
	// SetViolations are the authored modules that define violation as a set, which plugins
	// built on an agent library older than v0.7.1 cannot evaluate; PolicyIDRules are the
	// authored modules that declare policy_id, which plugins built before R74 ignore (R76).
	// Neither counts the policy_id the agent appends (Continued).
	SetViolations, PolicyIDRules []Site
	// Continued maps the modules the agent appended a continuity policy_id to (R82), by
	// path, to that policy_id.
	Continued map[string]string
	// Shadowed is set when plugins receive the bundle at the extends source's own path,
	// resolved to Dir inside each plugin's view (path shadowing, see internal/policyview):
	// Path is then Extends.PluginPath, and no continuity policy_id is appended, because the
	// path string alone keeps the vendor's evidence streams.
	Shadowed bool
}

// Options change how Materialize writes a bundle.
type Options struct {
	// Shadow asks for path shadowing: when the bundle extends a source whose plugin path
	// policyview.Shadowable accepts, plugins receive that path (Materialized.Shadowed) and
	// the tree is written without continuity policy_ids. Otherwise it is ignored.
	Shadow bool
}

// Materialize builds bundle name in the R17 order (extends tree, delete, modules, data),
// checks the data-file rule (R18), appends the continuity policy_id to the modules that
// continue a vendor file (R82) and writes the result write-once under l.Store.
func Materialize(ctx context.Context, l Layout, name string, b *agentconfig.PolicyBundle, resolve Resolver, opts ...Options) (*Materialized, error) {
	var opt Options
	for _, o := range opts {
		opt.Shadow = opt.Shadow || o.Shadow
	}
	if b == nil {
		return nil, PolicyErrors{{Bundle: name, Message: "bundle has no definition", Severity: agentconfig.SeverityError}}
	}
	if !agentconfig.BundleNamePattern.MatchString(name) {
		return nil, PolicyErrors{{Bundle: name, Message: "invalid bundle name", Severity: agentconfig.SeverityError}}
	}
	m := &Materialized{Name: name, Authored: map[string]bool{}, Continued: map[string]string{}}
	var errs PolicyErrors
	warn := func(p, format string, args ...any) {
		m.Warnings = append(m.Warnings, agentconfig.PolicyError{Bundle: name, Path: p, Message: fmt.Sprintf(format, args...), Severity: agentconfig.SeverityWarning})
	}
	fail := func(p, format string, args ...any) {
		errs = append(errs, agentconfig.PolicyError{Bundle: name, Path: p, Message: fmt.Sprintf(format, args...), Severity: agentconfig.SeverityError})
	}

	// 1. Base tree.
	files := map[string][]byte{}
	var vendorFiles map[string][]byte
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
			// The resolver output is the literal path plugins get for the source (R77), so a
			// client can build continuity ids from it even when no plugin loads the source
			// directly any more (R78).
			PluginPath: dir,
		}
		m.ExtendsDir = dir
		m.ExtendsIdentities = Identities(baseFiles)
		vendorFiles = baseFiles
		files = maps.Clone(baseFiles)
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

	// The authored constructs, before the agent adds anything.
	m.SetViolations, m.PolicyIDRules = authoredSites(files, m.Authored)

	// 6. Continuity: path shadowing, or else the continuity policy_id (R82).
	m.Shadowed = opt.Shadow && m.Extends != nil && policyview.Shadowable(m.ExtendsDir) == nil
	if m.Extends != nil && !m.Shadowed {
		m.Warnings = append(m.Warnings, continueVendorStreams(m, files, vendorFiles)...)
	}

	// 7. Write once.
	m.Digest = agentconfig.BundleTreeDigest(files)
	final := filepath.Join(l.Store, name, strings.TrimPrefix(m.Digest, agentconfig.TreeDigestPrefix))
	if err := writeOnce(final, files); err != nil {
		return nil, err
	}
	m.Dir = filepath.Join(final, treeDir)
	m.Path = m.Dir
	switch {
	case m.Shadowed:
		m.Path = m.ExtendsDir
	case symlinksSupported(l.Links):
		m.Path = filepath.Join(l.Links, name, treeDir)
	}

	// 8. Inventory: the tree as written, so Files matches Digest and the uploaded artifact.
	m.Files = inventory(files)
	slices.Sort(m.AuthoredTests)
	m.Identities = Identities(files)
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

// readTree reads a policy tree the way every consumer does (see policytree.ReadTree).
func readTree(dir string) (map[string][]byte, []string, error) {
	return policytree.ReadTree(dir)
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
			if mod := parseRego(p, files[p]); mod != nil {
				r.Package = packageOf(mod)
			}
		}
		out = append(out, r)
	}
	return out
}

const (
	// treeDir is the directory holding the policy tree inside a materialized directory, the
	// last component of the path plugins receive (like an OCI source's policies/).
	treeDir = "policies"
	// legacyCurrentLink is the per-bundle symlink of the R67 layout (<Store>/<name>/current
	// -> <hex>, plugins got <Store>/<name>/current/bundle). GC removes it (R82).
	legacyCurrentLink = "current"
	// treeMarker marks a complete materialized directory. It sits next to treeDir, outside
	// the tree.
	treeMarker = ".ccf-tree"
	// Name prefixes of transient entries in a bundle directory, and in Links.
	tmpPrefix         = ".tmp-"
	currentTmpPrefix  = ".current-"
	symlinkProbeEntry = ".symlink-probe-"
)

// writeOnce writes files under final/policies unless final is already complete: a temp dir
// (dirs 0755, files 0644) with the completion marker, renamed into place. Losing a rename
// race reuses the winner's directory.
func writeOnce(final string, files map[string][]byte) error {
	if complete(final) {
		return nil
	}
	if _, err := os.Lstat(final); err == nil {
		// A directory in an earlier layout (the tree directly under final before R67, or
		// under final/bundle before R82): rebuild it.
		if err := os.RemoveAll(final); err != nil {
			return err
		}
	}
	parent := filepath.Dir(final)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(parent, tmpPrefix+randomSuffix())
	if err := os.MkdirAll(filepath.Join(tmp, treeDir), 0o755); err != nil {
		return err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	for p, content := range files {
		dst := filepath.Join(tmp, treeDir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			cleanup()
			return err
		}
		if err := os.WriteFile(dst, content, 0o644); err != nil {
			cleanup()
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, treeMarker), nil, 0o644); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		cleanup()
		if complete(final) {
			return nil
		}
		return err
	}
	return nil
}

// complete reports whether final is a materialized directory in this layout: the marker and
// a real policies/ directory (an R67 directory has the marker and bundle/).
func complete(final string) bool {
	info, err := os.Stat(filepath.Join(final, treeMarker))
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	tree, err := os.Lstat(filepath.Join(final, treeDir))
	return err == nil && tree.IsDir()
}

func randomSuffix() string {
	var rnd [6]byte
	_, _ = rand.Read(rnd[:])
	return hex.EncodeToString(rnd[:])
}

var symlinkSupport sync.Map // root -> bool

// symlinksSupported reports, once per root, whether symlinks can be created under root
// (not on Windows without the privilege, nor on some network or FAT file systems).
func symlinksSupported(root string) bool {
	if v, ok := symlinkSupport.Load(root); ok {
		return v.(bool)
	}
	ok := func() bool {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return false
		}
		probe := filepath.Join(root, symlinkProbeEntry+randomSuffix())
		defer func() { _ = os.Remove(probe) }()
		return os.Symlink(".", probe) == nil
	}()
	symlinkSupport.Store(root, ok)
	return ok
}

// Activate points bundle name's stable path (Materialized.Path) at dir, a Materialized.Dir
// of that bundle under l.Store. The swap is atomic: a temporary symlink renamed over
// <Links>/<name>, so on Linux a reader resolving the stable path sees either the previous
// tree or the new one, never neither (macOS APFS may fail such a racing lookup with EINVAL).
// It is not a snapshot for a reader walking the tree while it is swapped either. Callers
// therefore swap only while no plugin of the previous configuration runs (the agent does it
// between two configuration runs, after the reload drain), and serialize Activate with GC.
// It is a no-op when the tree is already active or the file system has no symlinks (plugins
// then receive dir itself).
func Activate(l Layout, name, dir string) error {
	versionDir := filepath.Dir(filepath.Clean(dir))
	if filepath.Base(filepath.Clean(dir)) != treeDir || filepath.Dir(versionDir) != filepath.Join(l.Store, name) {
		return fmt.Errorf("activate %s: %s is not a materialized tree of the bundle", name, dir)
	}
	if !symlinksSupported(l.Links) {
		return nil
	}
	if !complete(versionDir) {
		return fmt.Errorf("activate %s: the materialized tree %s is missing", name, dir)
	}
	// An absolute target: the link lives next to the policy cache and the tree under the
	// state directory, which may be anywhere.
	target, err := filepath.Abs(versionDir)
	if err != nil {
		return fmt.Errorf("activate %s: %w", name, err)
	}
	link := filepath.Join(l.Links, name)
	if cur, err := os.Readlink(link); err == nil && cur == target {
		return nil
	}
	if err := os.MkdirAll(l.Links, 0o755); err != nil {
		return fmt.Errorf("activate %s: %w", name, err)
	}
	tmp := filepath.Join(l.Links, tmpPrefix+name+"-"+randomSuffix())
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("activate %s: %w", name, err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("activate %s: %w", name, err)
	}
	return nil
}

// GC removes materialized directories under l.Store except those in keep (Materialized.Dir
// values, or their parent), the one each bundle's stable link points to, and the perBundle
// newest per bundle, plus abandoned temporary entries, directories of an earlier layout and
// the R67 current links. Callers serialize GC with Activate.
func GC(l Layout, keep map[string]struct{}, perBundle int) error {
	var errs []error
	// Abandoned temporary links of Activate.
	if entries, err := os.ReadDir(l.Links); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), tmpPrefix) {
				errs = append(errs, os.Remove(filepath.Join(l.Links, e.Name())))
			}
		}
	}
	bundles, err := os.ReadDir(l.Store)
	if errors.Is(err, os.ErrNotExist) {
		return errors.Join(errs...)
	}
	if err != nil {
		return err
	}
	for _, b := range bundles {
		if !b.IsDir() {
			continue
		}
		bundleDir := filepath.Join(l.Store, b.Name())
		entries, err := os.ReadDir(bundleDir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		active := ""
		if target, err := os.Readlink(filepath.Join(l.Links, b.Name())); err == nil {
			active = absPath(target)
		}
		type dirInfo struct {
			path string
			mod  int64
		}
		var dirs []dirInfo
		for _, e := range entries {
			p := filepath.Join(bundleDir, e.Name())
			if strings.HasPrefix(e.Name(), tmpPrefix) || strings.HasPrefix(e.Name(), currentTmpPrefix) {
				errs = append(errs, os.RemoveAll(p))
				continue
			}
			if e.Name() == legacyCurrentLink && e.Type()&os.ModeSymlink != 0 {
				// Plugins no longer receive the R67 path, so nothing resolves it.
				errs = append(errs, os.Remove(p))
				continue
			}
			if !e.IsDir() {
				continue
			}
			if absPath(p) == active {
				continue
			}
			if _, ok := keep[p]; ok {
				continue
			}
			if _, ok := keep[filepath.Join(p, treeDir)]; ok {
				continue
			}
			if !complete(p) {
				// A tree of an earlier layout: Materialize rebuilds it when it is needed.
				errs = append(errs, os.RemoveAll(p))
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			dirs = append(dirs, dirInfo{p, info.ModTime().UnixNano()})
		}
		sort.Slice(dirs, func(i, j int) bool { return dirs[i].mod > dirs[j].mod })
		for i, d := range dirs {
			if i >= perBundle {
				errs = append(errs, os.RemoveAll(d.path))
			}
		}
	}
	return errors.Join(errs...)
}

// absPath returns p made absolute and cleaned, or p cleaned when that fails.
func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return filepath.Clean(p)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// SymlinksSupported reports, once per root, whether symlinks can be created under root.
func SymlinksSupported(root string) bool { return symlinksSupported(root) }
