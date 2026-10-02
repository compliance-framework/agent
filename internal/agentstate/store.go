// Package agentstate owns the agent's per-instance state directory: the stable instance ID
// (R31) and the remote configuration cache (R7).
//
// Layout (the OCI download caches under .compliance-framework/{plugins,policies} are shared
// and unchanged):
//
//	.compliance-framework/state/<key>/   key = hex(sha256(abs config path))[:16]; dir 0700
//	  instance-id                         0644, UUID + "\n"
//	  remote-config.json                  0600
//
// The package is a leaf: it never imports cmd.
package agentstate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
)

const (
	// StateRoot is the default parent of every per-config state directory, relative to the
	// working directory like the download caches.
	StateRoot = ".compliance-framework/state"

	instanceIDFile = "instance-id"
)

// Store is one agent instance's state directory. A Store whose directory is not writable
// keeps working in memory: the agent never fails because it cannot persist state.
type Store struct {
	dir      string
	logger   hclog.Logger
	writable bool

	mu     sync.Mutex
	id     uuid.UUID
	idSet  bool
	warned bool
}

// DefaultDir returns the default state directory for a config file: StateRoot/<key>, where key
// is the first 16 hex characters of sha256 of the absolute config path. Moving or renaming the
// config file therefore changes the directory and the instance ID (R52); containers should
// pin CCF_STATE_DIR.
func DefaultDir(configPath string) (string, error) {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return filepath.Abs(filepath.Join(StateRoot, hex.EncodeToString(sum[:])[:16]))
}

// Open prepares dir (MkdirAll 0700) and probes that it is writable. A failure is logged once
// as a WARN and the store continues in memory; it is never fatal.
func Open(dir string, logger hclog.Logger) *Store {
	if logger == nil {
		logger = hclog.NewNullLogger()
	}
	s := &Store{dir: dir, logger: logger.Named("state")}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.logger.Warn("State directory is not usable; state will not persist across restarts", "dir", dir, "error", err)
		return s
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		s.logger.Warn("State directory is not writable; state will not persist across restarts", "dir", dir, "error", err)
		return s
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	s.writable = true
	return s
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

// Writable reports whether the directory accepted a probe write at Open.
func (s *Store) Writable() bool { return s.writable }

// InstanceID returns this instance's stable ID and whether it is persisted:
//  1. a valid override (flag or CCF_INSTANCE_ID) wins and is not persisted;
//  2. otherwise the instance-id file;
//  3. otherwise a new ID, written atomically (a corrupt file is replaced);
//  4. if the store is not writable, the new ID lives in memory only (one WARN).
//
// The result is memoized: every call on one Store returns the same ID.
func (s *Store) InstanceID(override string) (uuid.UUID, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if o := strings.TrimSpace(override); o != "" {
		if id, err := uuid.Parse(o); err == nil {
			return id, false
		}
		s.logger.Warn("Ignoring invalid instance ID override", "value", o)
	}

	path := filepath.Join(s.dir, instanceIDFile)
	if s.idSet {
		return s.id, s.writable && fileExists(path)
	}

	if raw, err := os.ReadFile(path); err == nil {
		if id, err := uuid.Parse(strings.TrimSpace(string(raw))); err == nil {
			s.id, s.idSet = id, true
			return id, true
		}
		s.logger.Warn("Instance ID file is corrupt; replacing it", "path", path)
	}

	id := uuid.New()
	s.id, s.idSet = id, true
	if !s.writable {
		s.warnOnce("Instance ID is kept in memory only; a restart creates a new instance", "dir", s.dir)
		return id, false
	}
	if err := WriteFileAtomic(path, []byte(id.String()+"\n"), 0o644); err != nil {
		s.warnOnce("Could not persist the instance ID; a restart creates a new instance", "path", path, "error", err)
		return id, false
	}
	return id, true
}

func (s *Store) warnOnce(msg string, args ...any) {
	if s.warned {
		return
	}
	s.warned = true
	s.logger.Warn(msg, args...)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// WriteFileAtomic writes data to a temp file in path's directory, fsyncs it and renames it
// over path, so readers see either the old or the new content.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}
