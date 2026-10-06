package agentstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestCache_RoundTripAndIfNoneMatch(t *testing.T) {
	s := Open(t.TempDir(), nil)
	id := Identity{APIURL: "http://api.test", ClientID: "c"}
	c, err := s.LoadCache(id)
	if err != nil || c.IfNoneMatch() != "" {
		t.Fatalf("empty cache: %+v %v", c, err)
	}
	c.Applied = &OverlayRecord{Revision: 1, ETag: `"r1-a"`, Overlay: json.RawMessage(`{"plugins": {}}`), FetchedAt: time.Now().UTC()}
	if got := c.IfNoneMatch(); got != `"r1-a"` {
		t.Fatalf("IfNoneMatch falls back to applied, got %q", got)
	}
	c.Fetched = &OverlayRecord{Revision: 2, ETag: `W/"r2-b"`, Overlay: json.RawMessage(`{}`)}
	if got := c.IfNoneMatch(); got != `W/"r2-b"` {
		t.Fatalf("IfNoneMatch prefers the raw fetched ETag, got %q", got)
	}
	if err := s.SaveCache(c); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.LoadCache(id)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.Fetched.ETag != `W/"r2-b"` || loaded.Applied.Revision != 1 {
		t.Fatalf("round trip lost data: %+v", loaded)
	}
}

func TestCache_CorruptAndIdentity(t *testing.T) {
	s := Open(t.TempDir(), nil)
	id := Identity{APIURL: "http://api.test", ClientID: "c"}
	c, _ := s.LoadCache(id)
	c.Applied = &OverlayRecord{Revision: 1, ETag: `"r1-a"`, Overlay: json.RawMessage(`{}`)}
	if err := s.SaveCache(c); err != nil {
		t.Fatal(err)
	}
	other, err := s.LoadCache(Identity{APIURL: "http://api.test", ClientID: "d"})
	if err != nil || other.Applied != nil {
		t.Fatalf("an identity mismatch must yield an empty cache: %+v %v", other, err)
	}
	if err := os.WriteFile(s.CachePath(), []byte(`{"version":1,"checksum":"nope"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	empty, err := s.LoadCache(id)
	if !errors.Is(err, ErrCacheCorrupt) || empty == nil || empty.Applied != nil {
		t.Fatalf("expected ErrCacheCorrupt with an empty cache, got %+v %v", empty, err)
	}
}

// The overlay bytes, and so the no-ETag rejection key hashed from them, must not change across
// a save/load round trip: SaveCache re-indents a json.RawMessage and escapes <, > and &.
func TestCache_OverlayBytesSurviveRoundTrip(t *testing.T) {
	s := Open(t.TempDir(), nil)
	id := Identity{APIURL: "http://api.test", ClientID: "c"}
	fresh := json.RawMessage("{\n  \"plugins\": {\"p\": {\"config\": {\"q\": \"a<b && c>d\"}}},\n  \"x\": [1, 2]\n}")
	canon, err := CanonicalOverlay(fresh)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := CanonicalOverlay(canon); !bytes.Equal(again, canon) {
		t.Fatalf("CanonicalOverlay is not idempotent: %s != %s", again, canon)
	}

	c, _ := s.LoadCache(id)
	c.Fetched = &OverlayRecord{Revision: 3, Overlay: append(json.RawMessage(nil), fresh...)}
	c.Applied = &OverlayRecord{Revision: 2, ETag: `"r2-a"`, Overlay: append(json.RawMessage(nil), fresh...)}
	if err := s.SaveCache(c); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Fetched.Overlay, canon) {
		t.Fatalf("SaveCache must leave the canonical bytes in memory: %s", c.Fetched.Overlay)
	}
	for i := 0; i < 2; i++ {
		loaded, err := s.LoadCache(id)
		if err != nil {
			t.Fatalf("reload %d: %v", i, err)
		}
		if !bytes.Equal(loaded.Fetched.Overlay, canon) || !bytes.Equal(loaded.Applied.Overlay, canon) {
			t.Fatalf("reload %d changed the overlay bytes:\n got %s\nwant %s", i, loaded.Fetched.Overlay, canon)
		}
		if err := s.SaveCache(loaded); err != nil {
			t.Fatal(err)
		}
	}
}

// A cache written before overlays were canonicalized (an indented overlay, checksummed over its
// compact form) still loads, with its overlay in canonical form.
func TestCache_LoadsLegacyIndentedOverlay(t *testing.T) {
	s := Open(t.TempDir(), nil)
	id := Identity{APIURL: "http://api.test", ClientID: "c"}
	c := &Cache{Version: cacheVersion, Identity: id, Fetched: &OverlayRecord{Revision: 1, Overlay: json.RawMessage("{ \"a\": \"<\" }")}}
	sum, err := c.checksum()
	if err != nil {
		t.Fatal(err)
	}
	c.Checksum = sum
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.CachePath(), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := s.LoadCache(id)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(loaded.Fetched.Overlay), `{"a":"\u003c"}`; got != want {
		t.Fatalf("legacy overlay: got %s, want %s", got, want)
	}
}
