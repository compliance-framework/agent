package agentstate

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
)

func TestInstanceID_PersistedAndReused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	first, persisted := Open(dir, nil).InstanceID("")
	if !persisted {
		t.Fatal("expected the ID to be persisted")
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode = %v, want 0700", info.Mode().Perm())
	}
	second, persisted := Open(dir, nil).InstanceID("")
	if !persisted || second != first {
		t.Fatalf("expected the persisted ID to be reused: %s vs %s", first, second)
	}
}

func TestInstanceID_OverrideNotPersisted(t *testing.T) {
	dir := t.TempDir()
	override := uuid.New()
	id, persisted := Open(dir, nil).InstanceID(override.String())
	if id != override || persisted {
		t.Fatalf("override: got %s persisted=%v", id, persisted)
	}
	if _, err := os.Stat(filepath.Join(dir, instanceIDFile)); !os.IsNotExist(err) {
		t.Fatalf("override must not be written, stat err = %v", err)
	}
}

func TestInstanceID_ReadOnlyDirKeepsIDInMemory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	var logs bytes.Buffer
	logger := hclog.New(&hclog.LoggerOptions{Output: &logs, Level: hclog.Warn})
	s := Open(dir, logger)
	id, persisted := s.InstanceID("")
	if id == uuid.Nil || persisted {
		t.Fatalf("expected an in-memory ID, got %s persisted=%v", id, persisted)
	}
	if again, _ := s.InstanceID(""); again != id {
		t.Fatalf("in-memory ID must be stable for the process: %s vs %s", id, again)
	}
	if !strings.Contains(logs.String(), "[WARN]") {
		t.Fatalf("expected a WARN, got %q", logs.String())
	}
}

func TestInstanceID_CorruptFileReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, instanceIDFile)
	if err := os.WriteFile(path, []byte("not-a-uuid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	id, persisted := Open(dir, nil).InstanceID("")
	if !persisted {
		t.Fatal("expected the replacement to be persisted")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != id.String() {
		t.Fatalf("file holds %q, want %s", raw, id)
	}
}

func TestDefaultDir_DependsOnConfigPath(t *testing.T) {
	a, err := DefaultDir("/etc/ccf/a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DefaultDir("/etc/ccf/b.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two config paths must get two state dirs, got %s", a)
	}
	if !strings.Contains(filepath.ToSlash(a), StateRoot+"/") || len(filepath.Base(a)) != 16 {
		t.Fatalf("unexpected layout %s", a)
	}

	root := t.TempDir()
	idA, _ := Open(filepath.Join(root, filepath.Base(a)), nil).InstanceID("")
	idB, _ := Open(filepath.Join(root, filepath.Base(b)), nil).InstanceID("")
	if idA == idB {
		t.Fatal("two config paths must get two instance IDs")
	}
}
