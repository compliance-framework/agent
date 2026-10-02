package agentstate

import (
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
