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

	// Test Shard Locations
	shardMap := map[string]string{
		"shard0": "node1",
		"shard1": "node2",
	}
	r.SetShardLocations("file1", shardMap)

	got := r.GetShardLocations("file1")
	if len(got) != 2 {
		t.Fatalf("expected 2 shard locations, got %d", len(got))
	}
	if got["shard0"] != "node1" || got["shard1"] != "node2" {
		t.Errorf("unexpected shard mapping: %v", got)
	}

	// Test non-existent file
	got = r.GetShardLocations("file2")
	if len(got) != 0 {
		t.Errorf("expected 0 locations for non-existent file, got %d", len(got))
	}
}
