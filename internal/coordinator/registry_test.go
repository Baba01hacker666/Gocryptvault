package coordinator

import (
	"testing"
	"time"
)

func TestRegistry(t *testing.T) {
	r := NewRegistry()

	// Test Register
	r.Register("node1", "127.0.0.1:5000", 1000)
	healthy := r.GetHealthyNodes()
	if len(healthy) != 1 {
		t.Fatalf("expected 1 healthy node, got %d", len(healthy))
	}
	if healthy[0].ID != "node1" {
		t.Errorf("expected node1, got %s", healthy[0].ID)
	}

	// Test unhealthy node (mocking LastSeen)
	r.mu.Lock()
	r.nodes["node1"].LastSeen = time.Now().Add(-10 * time.Minute)
	r.mu.Unlock()

	healthy = r.GetHealthyNodes()
	if len(healthy) != 0 {
		t.Errorf("expected 0 healthy nodes, got %d", len(healthy))
	}
}
