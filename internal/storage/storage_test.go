package storage

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVaultErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gocryptvault_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	v := NewVault(tmpDir)
	pass := []byte("supersecret")

	// Unlock uninitialized
	if err := v.Unlock(pass); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("expected ErrNotInitialized, got %v", err)
	}

	// Init
	if err := v.Init(pass); err != nil {
		t.Fatalf("failed to init vault: %v", err)
	}

	// Init again
	if err := v.Init(pass); !errors.Is(err, ErrAlreadyInit) {
		t.Errorf("expected ErrAlreadyInit, got %v", err)
	}

	// Unlock with wrong password
	if err := v.Unlock([]byte("wrong")); !errors.Is(err, ErrInvalidPass) {
		t.Errorf("expected ErrInvalidPass, got %v", err)
	}
}

func TestVaultDeleteAndChangePassword(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gocryptvault_test2_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	v := NewVault(tmpDir)
	pass := []byte("secret")

	v.Init(pass)
	v.Unlock(pass)

	// Add file
	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("delete me"), 0644)
	v.AddFile(testFile)

	files, _ := v.ListFiles()
	if len(files) != 1 {
		t.Fatalf("expected 1 file")
	}
	fileID := files[0].ID

	// Delete File
	if err := v.DeleteFile(fileID); err != nil {
		t.Fatalf("failed to delete file: %v", err)
	}

	files, _ = v.ListFiles()
	if len(files) != 0 {
		t.Errorf("expected 0 files after deletion")
	}

	// Delete missing file
	if err := v.DeleteFile("missing"); !errors.Is(err, ErrFileNotFound) {
		t.Errorf("expected ErrFileNotFound, got %v", err)
	}

	// Change Password
	newPass := []byte("newsecret")
	if err := v.ChangePassword(pass, newPass); err != nil {
		t.Fatalf("failed to change password: %v", err)
	}

	// Lock and try to unlock with new password
	v.Lock()

	if err := v.Unlock(pass); err == nil {
		t.Errorf("expected error when unlocking with old password")
	}

	if err := v.Unlock(newPass); err != nil {
		t.Fatalf("failed to unlock with new password: %v", err)
	}
}
