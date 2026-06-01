package metadata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Baba01hacker666/Gocryptvault/internal/crypto"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
)

type MetadataDB struct {
	Files map[string]*types.FileRecord `json:"files"`
}

func NewMetadataDB() *MetadataDB {
	return &MetadataDB{
		Files: make(map[string]*types.FileRecord),
	}
}

func EncryptMetadata(db *MetadataDB, key []byte) ([]byte, error) {
	data, err := json.Marshal(db)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	return crypto.Encrypt(data, key)
}

// EncryptMetadataDeniable encrypts metadata and pads it to a fixed size.
func EncryptMetadataDeniable(db *MetadataDB, key []byte, size int) ([]byte, error) {
	data, err := json.Marshal(db)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	nonceSize := 24 // XChaCha20-Poly1305 nonce size
	tagSize := 16   // Poly1305 tag size
	maxPlaintextSize := size - nonceSize - tagSize

	if len(data) > maxPlaintextSize {
		return nil, fmt.Errorf("metadata too large for fixed size %d", size)
	}

	// Pad with null bytes
	paddedData := make([]byte, maxPlaintextSize)
	copy(paddedData, data)

	return crypto.Encrypt(paddedData, key)
}

func DecryptMetadata(encryptedData []byte, key []byte) (*MetadataDB, error) {
	if len(encryptedData) == 0 {
		return NewMetadataDB(), nil
	}

	data, err := crypto.Decrypt(encryptedData, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
	}

	// Trim null padding
	data = bytes.TrimRight(data, "\x00")

	var db MetadataDB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if db.Files == nil {
		db.Files = make(map[string]*types.FileRecord)
	}

	return &db, nil
}

func LoadEncryptedMetadata(path string, key []byte) (*MetadataDB, error) {
	encryptedData, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewMetadataDB(), nil // return empty DB if not found
		}
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	return DecryptMetadata(encryptedData, key)
}

func SaveEncryptedMetadata(path string, db *MetadataDB, key []byte) error {
	encryptedData, err := EncryptMetadata(db, key)
	if err != nil {
		return err
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

// LoadDeniableMetadata loads metadata from a 1MB deniable blob.
func LoadDeniableMetadata(path string, key []byte, offset int) (*MetadataDB, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read deniable blob: %w", err)
	}

	var encryptedData []byte
	if offset == 0 {
		encryptedData, err = ExtractDecoy(blob)
	} else {
		encryptedData, err = ExtractHidden(blob, offset)
	}

	if err != nil {
		return nil, err
	}

	return DecryptMetadata(encryptedData, key)
}

