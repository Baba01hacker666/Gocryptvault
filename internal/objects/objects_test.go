package objects

import (
	"bytes"
	"github.com/Baba01hacker666/Gocryptvault/internal/crypto"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRetrieveDeleteChunk(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gocryptvault_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	key, _ := crypto.GenerateRandomBytes(crypto.KeyLen)
	plaintext := []byte("hello chunk")

	// 1. Store
	chunkID, err := StoreChunk(tmpDir, plaintext, key)
	if err != nil {
		t.Fatalf("StoreChunk failed: %v", err)
	}
	if len(chunkID) == 0 {
		t.Fatalf("StoreChunk returned empty ID")
	}

	// 2. Verify file exists
	subDir := chunkID[:2]
	chunkPath := filepath.Join(tmpDir, subDir, chunkID)
	if _, err := os.Stat(chunkPath); os.IsNotExist(err) {
		t.Errorf("chunk file not created at %s", chunkPath)
	}

	// 3. Retrieve
	retrieved, err := RetrieveChunk(tmpDir, chunkID, key, true)
	if err != nil {
		t.Fatalf("RetrieveChunk failed: %v", err)
	}
	if !bytes.Equal(plaintext, retrieved) {
		t.Errorf("retrieved text %q does not match original %q", retrieved, plaintext)
	}

	// 4. Retrieve with wrong key
	wrongKey, _ := crypto.GenerateRandomBytes(crypto.KeyLen)
	_, err = RetrieveChunk(tmpDir, chunkID, wrongKey, true)
	if err == nil {
		t.Errorf("expected error when retrieving with wrong key")
	}

	// 5. Delete
	err = DeleteChunk(tmpDir, chunkID)
	if err != nil {
		t.Fatalf("DeleteChunk failed: %v", err)
	}
	if _, err := os.Stat(chunkPath); !os.IsNotExist(err) {
		t.Errorf("chunk file still exists after deletion")
	}
}

func TestInvalidChunk(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "gocryptvault_test_invalid_*")
	defer os.RemoveAll(tmpDir)

	key, _ := crypto.GenerateRandomBytes(crypto.KeyLen)

	_, err := RetrieveChunk(tmpDir, "a", key, true)
	if err == nil {
		t.Errorf("expected error for too short chunk ID")
	}

	err = DeleteChunk(tmpDir, "a")
	if err != nil {
		t.Errorf("expected no error for too short chunk ID in delete, got %v", err)
	}

	_, err = RetrieveChunk(tmpDir, "doesnotexist", key, true)
	if err == nil {
		t.Errorf("expected error for non-existent chunk")
	}
}

func TestErasureCoding(t *testing.T) {
	data := []byte("this is some data that will be sharded and reconstructed using reed-solomon erasure coding")
	originalSize := len(data)

	// 1. Shard
	shards, err := ShardData(data)
	if err != nil {
		t.Fatalf("ShardData failed: %v", err)
	}

	if len(shards) != DataShards+ParityShards {
		t.Errorf("expected %d shards, got %d", DataShards+ParityShards, len(shards))
	}

	// 2. Reconstruct with all shards
	reconstructed, err := ReconstructData(shards, originalSize)
	if err != nil {
		t.Fatalf("ReconstructData failed: %v", err)
	}
	if !bytes.Equal(data, reconstructed) {
		t.Errorf("reconstructed data does not match original")
	}

	// 3. Reconstruct with missing parity shards
	shards3 := make([][]byte, len(shards))
	copy(shards3, shards)
	shards3[DataShards] = nil
	shards3[DataShards+1] = nil
	reconstructed3, err := ReconstructData(shards3, originalSize)
	if err != nil {
		t.Fatalf("ReconstructData failed with missing parity: %v", err)
	}
	if !bytes.Equal(data, reconstructed3) {
		t.Errorf("reconstructed data with missing parity does not match original")
	}

	// 4. Reconstruct with missing data shards
	shards4 := make([][]byte, len(shards))
	copy(shards4, shards)
	shards4[0] = nil
	shards4[1] = nil
	reconstructed4, err := ReconstructData(shards4, originalSize)
	if err != nil {
		t.Fatalf("ReconstructData failed with missing data shards: %v", err)
	}
	if !bytes.Equal(data, reconstructed4) {
		t.Errorf("reconstructed data with missing data shards does not match original")
	}

	// 5. Fail with too many missing shards
	shards5 := make([][]byte, len(shards))
	copy(shards5, shards)
	shards5[0] = nil
	shards5[1] = nil
	shards5[2] = nil // 3 missing data shards, only 2 parity shards available
	_, err = ReconstructData(shards5, originalSize)
	if err == nil {
		t.Errorf("expected error with too many missing shards")
	}
}

func TestStoreRetrieveShards(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gocryptvault_shards_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	key, _ := crypto.GenerateRandomBytes(crypto.KeyLen)
	plaintext := []byte("this is some secret data that will be sharded")

	// 1. Store Shards
	shardIDs, ciphertextSize, err := StoreShards(tmpDir, plaintext, key)
	if err != nil {
		t.Fatalf("StoreShards failed: %v", err)
	}

	if len(shardIDs) != DataShards+ParityShards {
		t.Errorf("expected %d shards, got %d", DataShards+ParityShards, len(shardIDs))
	}

	// 2. Retrieve Shards
	retrieved, err := RetrieveShards(tmpDir, shardIDs, key, ciphertextSize)
	if err != nil {
		t.Fatalf("RetrieveShards failed: %v", err)
	}

	if !bytes.Equal(plaintext, retrieved) {
		t.Errorf("retrieved data does not match original")
	}

	// 3. Retrieve with some missing shards
	// Delete 2 shards (max we can lose with 2 parity shards)
	for i := 0; i < 2; i++ {
		subDir := shardIDs[i][:2]
		shardPath := filepath.Join(tmpDir, subDir, shardIDs[i])
		os.Remove(shardPath)
	}

	retrieved2, err := RetrieveShards(tmpDir, shardIDs, key, ciphertextSize)
	if err != nil {
		t.Fatalf("RetrieveShards failed with missing shards: %v", err)
	}

	if !bytes.Equal(plaintext, retrieved2) {
		t.Errorf("retrieved data with missing shards does not match original")
	}

	// 4. Fail with too many missing shards
	subDir := shardIDs[2][:2]
	shardPath := filepath.Join(tmpDir, subDir, shardIDs[2])
	os.Remove(shardPath)

	_, err = RetrieveShards(tmpDir, shardIDs, key, ciphertextSize)
	if err == nil {
		t.Errorf("expected error with too many missing shards")
	}
}
