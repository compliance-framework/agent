// Package policyview builds per-plugin working directories ("views") in which a plugin sees
// an inline policy bundle at the exact relative path of the source the bundle extends (path
// shadowing, prototype).
//
// Plugins seed evidence UUIDs from the path string the agent passes them (policy-manager:
// policy_file = <path>/<file>, label _policy_path = <path>). A plugin that keeps receiving the
// vendor's path string therefore keeps the vendor's evidence streams, whatever agent library
// it was built with. A view makes that path string resolve to the inline bundle's tree:
//
//	<view>/.compliance-framework/policies/<repo>/<tag>        -> <inline store>/<bundle>/<digest>   (symlink)
//	<view>/.compliance-framework/policies/<repo>/<tag>/policies                                      (real dir, inside the tree)
//
// The plugin process is started with the view as its working directory. The link sits at
// the path's parent, never at the leaf, because OPA's bundle loader loads nothing from a
// symlinked root directory but resolves a symlink earlier in the path like any other.
//
// Every other entry of the agent's working directory is mirrored into the view: each real
// directory of the view (the ancestors of the links) holds a symlink to every entry of the
// same directory in the agent's working directory that is not itself a view directory or a
// link. So every other relative path the plugin receives, or opens on its own, resolves as
// it does for the agent (reading and writing through the mirrored links), except new
// entries the plugin creates directly in a view directory, which stay in the view.
//
// Ownership (rule 1): the view directories and the shadow links are the agent's; any real
// (non-symlink) entry Ensure finds where it would put a mirror link was created by the
// plugin and is the plugin's. Ensure keeps it untouched (the plugin keeps seeing its own
// entry rather than the working directory's), warns once per view and name, and carries
// on: a plugin-owned entry never fails a run. A real entry at a shadow link's own path is a
// genuine conflict (the plugin would not see the bundle there), and Ensure fails with a
// *LinkConflictError. Plugin-owned entries go away with their view (GC), which never
// follows links.
//
// A view is content-addressed by its links and base: a new bundle revision is a new view, so
// nothing is ever swapped under a running plugin. Ensure is idempotent and only adds missing
// mirror links, so it can run before every plugin run.
//
// The package is a leaf: it imports only the standard library.
package policyview

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// TreeDir is the last component a shadowed path must have: the inline store keeps each
// bundle's tree in a real policies/ directory, which the view link's target contains.
const TreeDir = "policies"

// View is one plugin's working directory.
type View struct {
	// Dir is the view directory (absolute).
	Dir string
	// Base is the agent's working directory (absolute): what every relative path that is not
	// shadowed resolves against.
	Base string
	// Links maps a slash-separated path relative to the view to the absolute directory it
	// links to.
	Links map[string]string
	// Warn, when set, receives Ensure's warnings as a message and key/value pairs (an
	// hclog.Logger's Warn fits). Each plugin-owned entry is reported once per process.
	Warn func(msg string, args ...interface{})
}

// LinkConflictError is Ensure's error when a shadow link's path holds an entry that is not
// a symlink: only the plugin can have put it there, and the plugin would not see the
// bundle at its policy path.
type LinkConflictError struct {
	// View is the view directory, Link the slash-separated path relative to it.
	View, Link string
}

func (e *LinkConflictError) Error() string {
	return fmt.Sprintf("view %s: the shadowed policy path's link %s holds an entry the plugin created (not a symlink); "+
		"the agent does not remove plugin-owned entries: delete %s (the view is rebuilt) or stop the plugin replacing it",
		e.View, e.Link, filepath.Join(e.View, filepath.FromSlash(e.Link)))
}

// warned holds the "<view dir>\x00<name>" of the plugin-owned entries already warned about.
var warned sync.Map

// Shadowable reports whether a plugin path can be shadowed: a relative path, inside the
// working directory, with a parent below it, whose last component is TreeDir (every OCI
// source; a local source only when laid out the same way).
func Shadowable(pluginPath string) error {
	if pluginPath == "" {
		return errors.New("empty path")
	}
	if filepath.IsAbs(pluginPath) || filepath.VolumeName(pluginPath) != "" {
		return fmt.Errorf("%s is absolute; only relative paths can be shadowed", pluginPath)
	}
	clean := filepath.Clean(pluginPath)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is outside the working directory", pluginPath)
	}
	if filepath.Base(clean) != TreeDir {
		return fmt.Errorf("%s does not end in %s/", pluginPath, TreeDir)
	}
	if filepath.Dir(clean) == "." {
		return fmt.Errorf("%s has no parent directory to link", pluginPath)
	}
	return nil
}

// LinkOf is the view path linked for shadowed plugin path p (its cleaned parent).
func LinkOf(p string) string {
	return filepath.ToSlash(filepath.Dir(filepath.Clean(p)))
}

// Plan checks that a plugin whose policy paths are shadowed (shadowed plugin paths) and
// others (every other policy path it receives) can be given one view, and returns the view
// link of each shadowed path. It fails when:
//
//   - two shadowed paths are the same, or one's link is inside another's;
//   - another relative path resolves into a shadowed tree, or is itself a view directory or
//     sits directly in one (its leaf would be a mirrored symlink, which OPA does not load).
//
// Absolute paths are unaffected by the view.
func Plan(shadowed, others []string) (map[string]string, error) {
	links := map[string]string{}
	seen := map[string]string{}
	for _, p := range shadowed {
		if err := Shadowable(p); err != nil {
			return nil, err
		}
		link := LinkOf(p)
		if prev, dup := seen[link]; dup {
			return nil, fmt.Errorf("%s and %s are the same path", prev, p)
		}
		seen[link] = p
		links[p] = link
	}
	for a := range seen {
		for b := range seen {
			if a != b && within(b, a) {
				return nil, fmt.Errorf("%s is inside %s", seen[b], seen[a])
			}
		}
	}
	dirs := viewDirs(seen)
	for _, p := range others {
		if filepath.IsAbs(p) || filepath.VolumeName(p) != "" {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(p))
		for link, sp := range seen {
			if clean == link || within(clean, link) {
				return nil, fmt.Errorf("%s would resolve into the shadowed tree of %s", p, sp)
			}
		}
		if dirs[clean] {
			return nil, fmt.Errorf("%s is a parent of a shadowed path", p)
		}
		if parent := pathDir(clean); dirs[parent] {
			return nil, fmt.Errorf("%s would be a symlinked policy root in the view (its parent %s holds a shadowed path)", p, parent)
		}
	}
	return links, nil
}

// within reports whether slash path p is strictly inside dir.
func within(p, dir string) bool {
	return dir == "." || strings.HasPrefix(p, dir+"/")
}

func pathDir(p string) string {
	return filepath.ToSlash(filepath.Dir(filepath.FromSlash(p)))
}

// viewDirs are the real directories of a view with links: every proper ancestor of a link,
// and the view root ".".
func viewDirs[V any](links map[string]V) map[string]bool {
	dirs := map[string]bool{".": true}
	for link := range links {
		for d := pathDir(link); d != "." && !dirs[d]; d = pathDir(d) {
			dirs[d] = true
		}
	}
	return dirs
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,62}$`)

// DirFor is the view directory of plugin under root for a view with links over base:
// <root>/<plugin>/<hash of base and links>.
func DirFor(root, plugin, base string, links map[string]string) string {
	name := plugin
	if !safeName.MatchString(plugin) {
		sum := sha256.Sum256([]byte(plugin))
		name = "p-" + hex.EncodeToString(sum[:8])
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%d:%s\n", len(base), base)
	keys := sortedKeys(links)
	for _, k := range keys {
		_, _ = fmt.Fprintf(h, "%d:%s=%d:%s\n", len(k), k, len(links[k]), links[k])
	}
	return filepath.Join(root, name, hex.EncodeToString(h.Sum(nil))[:16])
}

// Ensure creates the view: its directories, its links, and the mirror links of the base's
// entries. It never removes or changes an entry that is already right, nor a plugin-owned
// one (a real entry where a mirror link would go, see the package doc), so it is safe to
// run while a plugin uses the view. It fails with a *LinkConflictError when a shadow link's
// path holds a real entry.
func (v View) Ensure() error {
	if !filepath.IsAbs(v.Dir) || !filepath.IsAbs(v.Base) {
		return fmt.Errorf("view %s: the view and base directories must be absolute", v.Dir)
	}
	dirs := viewDirs(v.Links)
	var errs []error
	for _, d := range sortedKeys(dirs) {
		if err := os.MkdirAll(filepath.Join(v.Dir, filepath.FromSlash(d)), 0o755); err != nil {
			return fmt.Errorf("view %s: %w", v.Dir, err)
		}
	}
	for _, link := range sortedKeys(v.Links) {
		err := ensureSymlink(filepath.Join(v.Dir, filepath.FromSlash(link)), v.Links[link])
		if errors.Is(err, errNotSymlink) {
			err = &LinkConflictError{View: v.Dir, Link: link}
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	for _, d := range sortedKeys(dirs) {
		entries, err := os.ReadDir(filepath.Join(v.Base, filepath.FromSlash(d)))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, e := range entries {
			child := e.Name()
			if d != "." {
				child = d + "/" + child
			}
			if _, linked := v.Links[child]; linked || dirs[child] {
				continue
			}
			target := filepath.Join(v.Base, filepath.FromSlash(child))
			if contains(target, v.Dir) {
				continue // never mirror a directory that holds the view itself
			}
			err := ensureSymlink(filepath.Join(v.Dir, filepath.FromSlash(child)), target)
			if errors.Is(err, errNotSymlink) {
				v.pluginOwned(child, target)
				continue
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("view %s: %w", v.Dir, err)
	}
	return nil
}

// pluginOwned warns, once per view and name, that the plugin's own entry name hides the
// working directory's entry target in the view.
func (v View) pluginOwned(name, target string) {
	if v.Warn == nil {
		return
	}
	if _, seen := warned.LoadOrStore(v.Dir+"\x00"+name, struct{}{}); seen {
		return
	}
	v.Warn("Plugin created an entry in its working directory (view) that the agent's working directory now also has; "+
		"the plugin keeps its own, and does not see the agent's (plugins should not create files relative to their working directory)",
		"view", v.Dir, "path", name, "hidden", target)
}

// Resolve returns the path the plugin opens for pluginPath, as seen from outside the view:
// relative paths under the view, absolute ones unchanged.
func (v View) Resolve(pluginPath string) string {
	if filepath.IsAbs(pluginPath) {
		return pluginPath
	}
	return filepath.Join(v.Dir, pluginPath)
}

// contains reports whether p is dir or inside it.
func contains(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// errNotSymlink is ensureSymlink's error when path holds something that is not a symlink,
// which it never touches.
var errNotSymlink = errors.New("exists and is not a symlink")

var tmpLinks atomic.Uint64

// ensureSymlink makes path a symlink to target: a no-op when it already is, a new link, or
// an atomic replacement (temporary link renamed over it) of a link to something else. It
// never removes or replaces anything but a symlink: a real entry at path is errNotSymlink.
func ensureSymlink(path, target string) error {
	cur, err := os.Readlink(path)
	switch {
	case err == nil && cur == target:
		return nil
	case err == nil:
		// A name of our own, so a failure never removes an entry someone else made.
		tmp := fmt.Sprintf("%s.tmp-link-%d-%d", path, os.Getpid(), tmpLinks.Add(1))
		if err := os.Symlink(target, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		return nil
	}
	if _, statErr := os.Lstat(path); statErr == nil {
		return fmt.Errorf("%s %w", path, errNotSymlink)
	}
	if err := os.Symlink(target, path); err != nil {
		if !os.IsExist(err) {
			return err
		}
		// Created meanwhile: a link (another Ensure) is fine, anything else is not ours.
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s %w", path, errNotSymlink)
		}
	}
	return nil
}

// GC removes the views under root (<root>/<plugin>/<hash>) that are not in keep (View.Dir
// values), with every entry in them, plugin-owned ones included. It never follows a link:
// a symlinked plugin directory is skipped, a symlinked view is removed as a link, and
// os.RemoveAll removes the links inside a view, not what they point to.
func GC(root string, keep map[string]struct{}) error {
	plugins, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range plugins {
		if !p.IsDir() {
			continue
		}
		pluginDir := filepath.Join(root, p.Name())
		views, err := os.ReadDir(pluginDir)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		left := 0
		for _, v := range views {
			dir := filepath.Join(pluginDir, v.Name())
			if _, ok := keep[dir]; ok {
				left++
				continue
			}
			err := os.RemoveAll(dir)
			if err == nil {
				forgetWarnings(dir)
			}
			errs = append(errs, err)
		}
		if left == 0 {
			_ = os.Remove(pluginDir)
		}
	}
	return errors.Join(errs...)
}

// forgetWarnings drops the warnings recorded for view dir, which is gone: a view rebuilt at
// the same directory warns again.
func forgetWarnings(dir string) {
	warned.Range(func(k, _ any) bool {
		if key, _ := k.(string); strings.HasPrefix(key, dir+"\x00") {
			warned.Delete(k)
		}
		return true
	})
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
