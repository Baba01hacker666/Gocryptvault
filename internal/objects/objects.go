package objects

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Baba01hacker666/Gocryptvault/internal/crypto"
	"github.com/klauspost/reedsolomon"
)

const ChunkSize = 4 * 1024 * 1024 // 4 MB
const DataShards = 4
const ParityShards = 2

func ShardData(data []byte) ([][]byte, error) {
	enc, err := reedsolomon.New(DataShards, ParityShards)
	if err != nil {
		return nil, err
	}
	shards, err := enc.Split(data)
	if err != nil {
		return nil, err
	}
	if err := enc.Encode(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

func ReconstructData(shards [][]byte, originalSize int) ([]byte, error) {
	enc, err := reedsolomon.New(DataShards, ParityShards)
	if err != nil {
		return nil, err
	}
	if err := enc.Reconstruct(shards); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := enc.Join(&b, shards, originalSize); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func compressAndEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Compress data
	var b bytes.Buffer
	zw, _ := flate.NewWriter(&b, flate.BestSpeed)
	if _, err := zw.Write(plaintext); err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("failed to close compressor: %w", err)
	}

	compressedData := b.Bytes()
	var finalData []byte
	if len(compressedData) < len(plaintext) {
		// Use compressed
		finalData = make([]byte, 1+len(compressedData))
		finalData[0] = 1 // compressed marker
		copy(finalData[1:], compressedData)
	} else {
		// Use uncompressed
		finalData = make([]byte, 1+len(plaintext))
		finalData[0] = 0 // uncompressed marker
		copy(finalData[1:], plaintext)
	}

	ciphertext, err := crypto.Encrypt(finalData, key)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}
	return ciphertext, nil
}

func decryptAndDecompress(ciphertext []byte, key []byte) ([]byte, error) {
	decryptedData, err := crypto.Decrypt(ciphertext, key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	if len(decryptedData) == 0 {
		return nil, fmt.Errorf("decrypted data is empty")
	}

	isCompressed := decryptedData[0] == 1
	payload := decryptedData[1:]

	if isCompressed {
		zr := flate.NewReader(bytes.NewReader(payload))
		decompressedData, err := io.ReadAll(zr)
		zr.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to decompress data: %w", err)
		}
		return decompressedData, nil
	}

	return payload, nil
}

// StoreShards compresses, encrypts, and shards data using Reed-Solomon erasure coding.
// Returns a list of shard IDs and the size of the ciphertext before sharding.
func StoreShards(objectsDir string, plaintext []byte, key []byte) ([]string, int, error) {
	ciphertext, err := compressAndEncrypt(plaintext, key)
	if err != nil {
		return nil, 0, err
	}

	shards, err := ShardData(ciphertext)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to shard ciphertext: %w", err)
	}

	shardIDs := make([]string, len(shards))
	for i, shard := range shards {
		hash := sha256.Sum256(shard)
		shardID := hex.EncodeToString(hash[:])
		shardIDs[i] = shardID

		subDir := shardID[:2]
		shardDir := filepath.Join(objectsDir, subDir)
		if err := os.MkdirAll(shardDir, 0700); err != nil {
			return nil, 0, fmt.Errorf("failed to create shard directory: %w", err)
		}

		shardPath := filepath.Join(shardDir, shardID)
		if _, err := os.Stat(shardPath); err == nil {
			continue // Already exists
		}

		tempPath := filepath.Join(shardDir, shardID+".tmp")
		if err := os.WriteFile(tempPath, shard, 0600); err != nil {
			return nil, 0, fmt.Errorf("failed to write shard file: %w", err)
		}
		if err := os.Rename(tempPath, shardPath); err != nil {
			os.Remove(tempPath)
			return nil, 0, fmt.Errorf("failed to rename temp shard file: %w", err)
		}
	}

	return shardIDs, len(ciphertext), nil
}

// RetrieveShards reconstructs, decrypts, and decompresses data from shards.
func RetrieveShards(objectsDir string, shardIDs []string, key []byte, originalCiphertextSize int) ([]byte, error) {
	shards := make([][]byte, len(shardIDs))
	for i, shardID := range shardIDs {
		if len(shardID) < 2 {
			shards[i] = nil
			continue
		}
		subDir := shardID[:2]
		shardPath := filepath.Join(objectsDir, subDir, shardID)
		data, err := os.ReadFile(shardPath)
		if err != nil {
			shards[i] = nil
		} else {
			shards[i] = data
		}
	}

	ciphertext, err := ReconstructData(shards, originalCiphertextSize)
	if err != nil {
		return nil, fmt.Errorf("failed to reconstruct ciphertext: %w", err)
	}

	return decryptAndDecompress(ciphertext, key)
}

// StoreChunk encrypts a chunk and saves it in the objects directory.
// Deprecated: Use StoreShards instead.
func StoreChunk(objectsDir string, plaintext []byte, key []byte) (string, error) {
	ciphertext, err := compressAndEncrypt(plaintext, key)
	if err != nil {
		return "", err
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

	// Deduplication
	if _, err := os.Stat(chunkPath); err == nil {
		return chunkID, nil // Chunk already exists
	}

	// Atomic write
	tempPath := filepath.Join(chunkDir, chunkID+".tmp")
	if err := os.WriteFile(tempPath, ciphertext, 0600); err != nil {
		return "", fmt.Errorf("failed to write chunk file: %w", err)
	}
	if err := os.Rename(tempPath, chunkPath); err != nil {
		os.Remove(tempPath)
		return "", fmt.Errorf("failed to rename temp chunk file: %w", err)
	}

	return chunkID, nil
}

// RetrieveChunk reads an encrypted chunk from disk and decrypts it.
// Deprecated: Use RetrieveShards instead.
func RetrieveChunk(objectsDir string, chunkID string, key []byte, hasHeader bool) ([]byte, error) {
	if len(chunkID) < 2 {
		return nil, fmt.Errorf("invalid chunk ID")
	}

	subDir := chunkID[:2]
	chunkPath := filepath.Join(objectsDir, subDir, chunkID)

	ciphertext, err := os.ReadFile(chunkPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read chunk %s: %w", chunkID, err)
	}

	if !hasHeader {
		// Old chunks without compression header
		return crypto.Decrypt(ciphertext, key)
	}

	return decryptAndDecompress(ciphertext, key)
}

// DeleteChunk removes a chunk from disk securely.
func DeleteChunk(objectsDir string, chunkID string) error {
	if len(chunkID) < 2 {
		return nil
	}
	subDir := chunkID[:2]
	chunkPath := filepath.Join(objectsDir, subDir, chunkID)

	if info, err := os.Stat(chunkPath); err == nil && info.Size() > 0 {
		if f, err := os.OpenFile(chunkPath, os.O_WRONLY, 0); err == nil {
			size := info.Size()
			buf := make([]byte, 4096)

			// Pass 1: Zeros
			for i := range buf {
				buf[i] = 0x00
			}
			overwritePass(f, size, buf)

			// Pass 2: Ones
			for i := range buf {
				buf[i] = 0xFF
			}
			overwritePass(f, size, buf)

			// Pass 3: Random
			for i := int64(0); i < size; i += int64(len(buf)) {
				randomData, _ := crypto.GenerateRandomBytes(uint32(len(buf)))
				copy(buf, randomData)
				// We don't bother strictly with n size here since it's just wiping
			}
			overwritePass(f, size, buf)

			f.Close()
		}
	}

	return os.Remove(chunkPath)
}

func overwritePass(f *os.File, size int64, buf []byte) error {
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	written := int64(0)
	for written < size {
		n := size - written
		if n > int64(len(buf)) {
			n = int64(len(buf))
		}
		w, err := f.Write(buf[:n])
		if err != nil {
			return err
		}
		written += int64(w)
	}
	return f.Sync()
}
