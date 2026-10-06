package cmd

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"
)

func TestHeartbeatUsesStableInstanceIDAcrossRuns(t *testing.T) {
	id := uuid.New()
	ar := NewAgentRunner(WithInstanceID(id))
	ar.UpdateConfig(newTestAgentConfig("http://example.test", nil))
	var seen []uuid.UUID
	var mu sync.Mutex
	ar.sendHeartbeatFunc = func(_ context.Context, got uuid.UUID) error {
		mu.Lock()
		seen = append(seen, got)
		mu.Unlock()
		return nil
	}
	for i := 0; i < 2; i++ {
		c, err := ar.setupHeartbeatCron(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Entries() {
			e.Job.Run()
		}
	}
	if len(seen) != 2 || seen[0] != id || seen[1] != id {
		t.Fatalf("heartbeats used %v, want %s twice", seen, id)
	}
}
