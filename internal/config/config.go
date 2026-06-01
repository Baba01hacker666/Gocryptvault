package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Version      int    `json:"version"`
	KDF          string `json:"kdf"`
	Cipher       string `json:"cipher"`
	Created      int64  `json:"created"`
	Salt         []byte `json:"salt"`
	MasterKeyEnc []byte `json:"master_key_enc"`
	MetaKeyEnc   []byte `json:"meta_key_enc"`
}

func GetVaultPath() string {
	if p := os.Getenv("GOCRYPTVAULT_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./.vaultfs" // fallback
	}
	return filepath.Join(home, ".vaultfs")
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}
