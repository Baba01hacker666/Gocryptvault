package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Baba01hacker666/Gocryptvault/internal/storage"
)

func TestMetadataCacheEffect(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault_perf_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	v := storage.NewVault(tmpDir)
	pass := []byte("password")
	if err := v.Init(pass); err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(pass); err != nil {
		t.Fatal(err)
	}

	// Add 200 files to build a non-trivial metadata file
	for i := 0; i < 200; i++ {
		fname := fmt.Sprintf("file%d.txt", i)
		fpath := filepath.Join(tmpDir, fname)
		if err := os.WriteFile(fpath, []byte("some content"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := v.AddFile(fpath, fname); err != nil {
			t.Fatal(err)
		}
	}

	// Create a NEW vault instance to ensure cold cache
	v2 := storage.NewVault(tmpDir)
	if err := v2.Unlock(pass); err != nil {
		t.Fatal(err)
	}

	// First call (cold cache)
	start := time.Now()
	_, err = v2.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	coldDuration := time.Since(start)

	// Second call (warm cache)
	start = time.Now()
	_, err = v2.ListFiles()
	if err != nil {
		t.Fatal(err)
	}
	warmDuration := time.Since(start)

	t.Logf("Cold ListFiles (200 files): %v", coldDuration)
	t.Logf("Warm ListFiles (200 files): %v", warmDuration)

	if warmDuration >= coldDuration/5 {
		t.Errorf("Warm call not significantly faster. Cold: %v, Warm: %v", coldDuration, warmDuration)
	}
}
