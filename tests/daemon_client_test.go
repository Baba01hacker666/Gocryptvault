package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
)

func TestDaemonClientAddExport(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gocryptvault_daemon_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Override config vault path
	originalVaultPath := os.Getenv("GOCRYPTVAULT_PATH")
	os.Setenv("GOCRYPTVAULT_PATH", tmpDir)
	defer os.Setenv("GOCRYPTVAULT_PATH", originalVaultPath)

	// Initialize vault directly
	v := storage.NewVault(tmpDir)
	pass := []byte("testpass")
	if err := v.Init(pass); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	// Start daemon in background
	go func() {
		if err := daemon.RunServer(); err != nil {
			fmt.Printf("daemon server error: %v\n", err)
		}
	}()

	// Wait for socket to appear
	socketPath := filepath.Join(tmpDir, daemon.SocketName)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	c, err := client.NewClient()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer c.Close()

	// Unlock via RPC
	unlocked, err := c.Unlock(pass)
	if err != nil {
		t.Fatalf("failed to unlock via RPC: %v", err)
	}
	if !unlocked {
		t.Fatal("vault not unlocked")
	}

	// 1. Test AddFile
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("hello world"), 0644)
	err = c.AddFile(testFile, "test.txt")
	if err != nil {
		t.Fatalf("failed to add file: %v", err)
	}

	// 2. Test ListFiles
	files, err := c.ListFiles()
	if err != nil {
		t.Fatalf("failed to list files: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file, got %d", len(files))
	}
	fileID := files[0].ID

	// 3. Test ExportFile
	outDir := filepath.Join(tmpDir, "out")
	os.Mkdir(outDir, 0755)
	err = c.ExportFile(fileID, outDir)
	if err != nil {
		t.Fatalf("failed to export file: %v", err)
	}

	exportedContent, err := os.ReadFile(filepath.Join(outDir, "test.txt"))
	if err != nil {
		t.Fatalf("failed to read exported file: %v", err)
	}
	if string(exportedContent) != "hello world" {
		t.Errorf("exported content mismatch: got %q, want %q", exportedContent, "hello world")
	}
}
