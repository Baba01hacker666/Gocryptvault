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
