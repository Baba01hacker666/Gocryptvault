package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoadConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gocryptvault_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.enc")

	cfg := &Config{
		Version:      1,
		KDF:          "argon2id",
		Cipher:       "xchacha20poly1305",
		Created:      123456789,
		Salt:         []byte("salt"),
		MasterKeyEnc: []byte("master_key"),
		MetaKeyEnc:   []byte("meta_key"),
	}

	err = SaveConfig(configPath, cfg)
	if err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	loadedCfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if loadedCfg.Version != cfg.Version || loadedCfg.KDF != cfg.KDF {
		t.Errorf("loaded config does not match saved config")
	}

	// Test load non-existent
	_, err = LoadConfig(filepath.Join(tmpDir, "nonexistent.enc"))
	if err == nil {
		t.Errorf("expected error when loading non-existent config")
	}
}

func TestGetVaultPath(t *testing.T) {
	path := GetVaultPath()
	if path == "" {
		t.Errorf("GetVaultPath returned empty string")
	}
}
