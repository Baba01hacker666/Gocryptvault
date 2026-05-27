package objects

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"vaultfs/internal/crypto"
)

const ChunkSize = 4 * 1024 * 1024 // 4 MB

// StoreChunk encrypts a chunk and saves it in the objects directory.
// Returns the hex-encoded SHA-256 hash of the ciphertext (which is used as the chunk ID).
func StoreChunk(objectsDir string, plaintext []byte, key []byte) (string, error) {
	ciphertext, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt chunk: %w", err)
	}

	hash := sha256.Sum256(ciphertext)
	chunkID := hex.EncodeToString(hash[:])

	// Subdirectory structure for scale, e.g., objects/ab/abcd...
	subDir := chunkID[:2]
	chunkDir := filepath.Join(objectsDir, subDir)
	if err := os.MkdirAll(chunkDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create object directory: %w", err)
	}

	chunkPath := filepath.Join(chunkDir, chunkID)
	if err := os.WriteFile(chunkPath, ciphertext, 0600); err != nil {
		return "", fmt.Errorf("failed to write chunk file: %w", err)
	}

	return chunkID, nil
}

// RetrieveChunk reads an encrypted chunk from disk and decrypts it.
func RetrieveChunk(objectsDir string, chunkID string, key []byte) ([]byte, error) {
	if len(chunkID) < 2 {
		return nil, fmt.Errorf("invalid chunk ID")
	}

	subDir := chunkID[:2]
	chunkPath := filepath.Join(objectsDir, subDir, chunkID)

	ciphertext, err := os.ReadFile(chunkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk %s: %w", chunkID, err)
	}

	plaintext, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt chunk %s: %w", chunkID, err)
	}

	return plaintext, nil
}

// DeleteChunk removes a chunk from disk.
func DeleteChunk(objectsDir string, chunkID string) error {
	if len(chunkID) < 2 {
		return nil
	}
	subDir := chunkID[:2]
	chunkPath := filepath.Join(objectsDir, subDir, chunkID)
	return os.Remove(chunkPath)
}
