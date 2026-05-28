package metadata

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Baba01hacker666/Gocryptvault/internal/crypto"
)

type FileRecord struct {
	ID         string   `json:"id"`
	Filename   string   `json:"filename"`
	Size       int64    `json:"size"`
	MimeType   string   `json:"mime_type"`
	Compressed bool     `json:"compressed"`
	Chunks     []string `json:"chunks"`
	Created    int64    `json:"created"`
	Modified   int64    `json:"modified"`
}

type MetadataDB struct {
	Files map[string]*FileRecord `json:"files"`
}

func NewMetadataDB() *MetadataDB {
	return &MetadataDB{
		Files: make(map[string]*FileRecord),
	}
}

func LoadEncryptedMetadata(path string, key []byte) (*MetadataDB, error) {
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewMetadataDB(), nil // return empty DB if not found
		}
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	if len(encryptedData) == 0 {
		return NewMetadataDB(), nil
	}

	data, err := crypto.Decrypt(encryptedData, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	var db MetadataDB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if db.Files == nil {
		db.Files = make(map[string]*FileRecord)
	}

	return &db, nil
}

func SaveEncryptedMetadata(path string, db *MetadataDB, key []byte) error {
	data, err := json.Marshal(db)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	encryptedData, err := crypto.Encrypt(data, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt metadata: %w", err)
	}

	tempPath := filepath.Join(filepath.Dir(path), "metadata.tmp")
	if err := os.WriteFile(tempPath, encryptedData, 0600); err != nil {
		return fmt.Errorf("failed to write temporary metadata file: %w", err)
	}

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to atomic rename metadata file: %w", err)
	}

	return nil
}
