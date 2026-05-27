package metadata

import (
	"os"
	"path/filepath"
	"testing"
	"vaultfs/internal/crypto"
)

func TestNewMetadataDB(t *testing.T) {
	db := NewMetadataDB()
	if db.Files == nil {
		t.Errorf("NewMetadataDB should initialize Files map")
	}
}

func TestSaveAndLoadEncryptedMetadata(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vaultfs_metadata_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	metaPath := filepath.Join(tmpDir, "metadata.enc")
	key, _ := crypto.GenerateRandomBytes(crypto.KeyLen)

	// 1. Load missing file (should return empty DB without error)
	db, err := LoadEncryptedMetadata(metaPath, key)
	if err != nil {
		t.Fatalf("expected no error for missing metadata, got: %v", err)
	}
	if len(db.Files) != 0 {
		t.Errorf("expected empty DB for missing metadata")
	}

	// 2. Save DB
	db.Files["file1"] = &FileRecord{
		ID:       "file1",
		Filename: "test.txt",
		Size:     100,
		Chunks:   []string{"chunk1", "chunk2"},
	}

	err = SaveEncryptedMetadata(metaPath, db, key)
	if err != nil {
		t.Fatalf("failed to save metadata: %v", err)
	}

	// 3. Load DB
	loadedDb, err := LoadEncryptedMetadata(metaPath, key)
	if err != nil {
		t.Fatalf("failed to load metadata: %v", err)
	}

	if record, ok := loadedDb.Files["file1"]; !ok {
		t.Errorf("loaded DB missing file1")
	} else if record.Filename != "test.txt" {
		t.Errorf("filename mismatch: got %s, want test.txt", record.Filename)
	}

	// 4. Load with wrong key
	wrongKey, _ := crypto.GenerateRandomBytes(crypto.KeyLen)
	_, err = LoadEncryptedMetadata(metaPath, wrongKey)
	if err == nil {
		t.Errorf("expected error when loading with wrong key")
	}

	// 5. Load empty file
	os.WriteFile(metaPath, []byte(""), 0600)
	emptyDb, err := LoadEncryptedMetadata(metaPath, key)
	if err != nil {
		t.Fatalf("expected no error when loading empty file, got %v", err)
	}
	if len(emptyDb.Files) != 0 {
		t.Errorf("expected empty DB when loading empty file")
	}
}
