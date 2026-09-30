package agentstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	cacheFile    = "remote-config.json"
	cacheVersion = 1
)

// ErrCacheCorrupt is returned by LoadCache when the cache file does not parse or its checksum
// does not match. The agent reports failed/cache-corrupt once and continues without the cache.
var ErrCacheCorrupt = errors.New("remote config cache corrupt")

// Identity binds a cache to the API and credentials it was fetched with (R7). A cache whose
// identity differs from the current one is discarded, so a new client_id or API URL never
// applies another agent's overlay.
type Identity struct {
	APIURL   string `json:"api_url"`
	ClientID string `json:"client_id"`
}

// OverlayRecord is one overlay document received from the API.
type OverlayRecord struct {
	Revision int64 `json:"revision"`
	// ETag is the RAW ETag header of the 200 response (opaque, e.g. "r<rev>-<uuid>"). It is
	// sent back verbatim as If-None-Match and never built from a revision number (R7).
	ETag      string          `json:"etag"`
	Overlay   json.RawMessage `json:"overlay"`
	FetchedAt time.Time       `json:"fetched_at"`
}

// RejectedRecord remembers that a fetched overlay was rejected against a given base, so it
// is not re-prepared on every poll. It is keyed by (ETag, BaseFingerprint); the revision is
// informational only because a reset API can reuse revision numbers, except when the
// response carried no ETag: then (Revision, OverlaySHA256) stands in for it.
type RejectedRecord struct {
	Revision int64  `json:"revision"`
	ETag     string `json:"etag"`
	// OverlaySHA256 keys the record with the revision when the response had no ETag.
	OverlaySHA256   string `json:"overlay_sha256,omitempty"`
	BaseFingerprint string `json:"base_fingerprint"`
	Status          string `json:"status"`
	Reason          string `json:"reason"`
	Error           string `json:"error"`
}

// Cache is the persisted remote configuration state (0600, it may hold values an admin typed).
type Cache struct {
	Version  int             `json:"version"`
	Identity Identity        `json:"identity"`
	Applied  *OverlayRecord  `json:"applied,omitempty"`
	Fetched  *OverlayRecord  `json:"fetched,omitempty"` // newest 200 body; may be the rejected one
	Rejected *RejectedRecord `json:"rejected,omitempty"`
	Checksum string          `json:"checksum"` // sha256 of the JSON with Checksum = ""
}

// IfNoneMatch is the ETag to present on the next fetch: the last 200's raw ETag, falling back
// to the applied one, or "" for an unconditional fetch.
func (c *Cache) IfNoneMatch() string {
	if c == nil {
		return ""
	}
	if c.Fetched != nil && c.Fetched.ETag != "" {
		return c.Fetched.ETag
	}
	if c.Applied != nil {
		return c.Applied.ETag
	}
	return ""
}

func (c Cache) checksum() (string, error) {
	c.Checksum = ""
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// CachePath returns the cache file path.
func (s *Store) CachePath() string { return filepath.Join(s.dir, cacheFile) }

// LoadCache reads the cache for identity id. A missing file yields an empty cache. A corrupt
// file yields an empty cache and ErrCacheCorrupt. A cache bound to another identity is
// discarded (empty cache, nil error, one INFO).
func (s *Store) LoadCache(id Identity) (*Cache, error) {
	empty := &Cache{Version: cacheVersion, Identity: id}
	raw, err := os.ReadFile(s.CachePath())
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, fmt.Errorf("%w: %v", ErrCacheCorrupt, err)
	}
	var c Cache
	if err := json.Unmarshal(raw, &c); err != nil {
		return empty, fmt.Errorf("%w: %v", ErrCacheCorrupt, err)
	}
	want, err := c.checksum()
	if err != nil || c.Checksum != want || c.Version != cacheVersion {
		return empty, fmt.Errorf("%w: checksum or version mismatch", ErrCacheCorrupt)
	}
	if c.Identity != id {
		s.logger.Info("Discarding the remote config cache: it belongs to another API URL or client ID")
		return empty, nil
	}
	return &c, nil
}

// SaveCache writes the cache atomically (temp file, fsync, rename) with mode 0600. It is a
// no-op error when the store is not writable.
func (s *Store) SaveCache(c *Cache) error {
	if !s.writable {
		return errors.New("state directory is not writable")
	}
	c.Version = cacheVersion
	sum, err := c.checksum()
	if err != nil {
		return err
	}
	c.Checksum = sum
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.CachePath(), raw, 0o600)
}
