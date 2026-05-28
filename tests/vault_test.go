package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
)

func TestVaultLifecycle(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gocryptvault_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	v := storage.NewVault(tmpDir)

	pass := []byte("supersecret")

	// 1. Init
	if err := v.Init(pass); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	// 2. Unlock
	if err := v.Unlock(pass); err != nil {
		t.Fatalf("failed to unlock vault: %v", err)
	}

	// 3. Add File
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("test content"), 0644)

	if err := v.AddFile(testFile); err != nil {
		t.Fatalf("failed to add file: %v", err)
	}

	// 4. List Files
	files, err := v.ListFiles()
	if err != nil {
		t.Fatalf("failed to list files: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	fileID := files[0].ID

	// 5. Export File
	outDir := filepath.Join(tmpDir, "out")
	os.Mkdir(outDir, 0755)
	if err := v.ExportFile(fileID, outDir); err != nil {
		t.Fatalf("failed to export file: %v", err)
	}

	exportedContent, err := os.ReadFile(filepath.Join(outDir, "test.txt"))
	if string(exportedContent) != "test content" {
		t.Errorf("exported content mismatch: got %q", exportedContent)
	}

	// 6. Lock
	v.Lock()
}
