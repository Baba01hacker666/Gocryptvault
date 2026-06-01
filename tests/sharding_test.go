package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
)

func TestShardingRecovery(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gocryptvault_sharding_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	v := storage.NewVault(tmpDir)
	pass := []byte("shardingpass")

	if err := v.Init(pass); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}
	if err := v.Unlock(pass); err != nil {
		t.Fatalf("failed to unlock vault: %v", err)
	}

	testContent := []byte("this is a test content that will be sharded and then some shards will be deleted to test recovery")
	testFile := filepath.Join(tmpDir, "test_sharding.txt")
	os.WriteFile(testFile, testContent, 0644)

	if err := v.AddFile(testFile, "test_sharding.txt"); err != nil {
		t.Fatalf("failed to add file: %v", err)
	}

	files, err := v.ListFiles()
	if err != nil {
		t.Fatalf("failed to list files: %v", err)
	}
	record := files[0]
	
	// We expect 1 chunk with 6 shards (4 data + 2 parity)
	if len(record.Chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(record.Chunks))
	}
	if len(record.Chunks[0].Shards) != 6 {
		t.Fatalf("expected 6 shards, got %d", len(record.Chunks[0].Shards))
	}

	// 1. Manually delete 2 shards (should still be able to recover)
	for i := 0; i < 2; i++ {
		shardID := record.Chunks[0].Shards[i].ShardID
		shardPath := filepath.Join(tmpDir, "objects", shardID[:2], shardID)
		if err := os.Remove(shardPath); err != nil {
			t.Fatalf("failed to delete shard %d: %v", i, err)
		}
	}

	outDir := filepath.Join(tmpDir, "out_recovered")
	os.Mkdir(outDir, 0755)
	if err := v.ExportFile(record.ID, outDir); err != nil {
		t.Fatalf("failed to export file with 2 missing shards: %v", err)
	}

	exportedContent, err := os.ReadFile(filepath.Join(outDir, "test_sharding.txt"))
	if string(exportedContent) != string(testContent) {
		t.Errorf("recovered content mismatch with 2 missing shards")
	}

	// 2. Manually delete 1 more shard (total 3 missing, should fail as we only have 2 parity)
	shardID := record.Chunks[0].Shards[2].ShardID
	shardPath := filepath.Join(tmpDir, "objects", shardID[:2], shardID)
	if err := os.Remove(shardPath); err != nil {
		t.Fatalf("failed to delete 3rd shard: %v", err)
	}

	outDirFail := filepath.Join(tmpDir, "out_failed")
	os.Mkdir(outDirFail, 0755)
	err = v.ExportFile(record.ID, outDirFail)
	if err == nil {
		t.Fatalf("expected export to fail with 3 missing shards, but it succeeded")
	}
	t.Logf("Got expected error with 3 missing shards: %v", err)
}
