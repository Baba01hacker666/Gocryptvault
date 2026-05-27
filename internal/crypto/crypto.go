package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ArgonTime    = 4
	ArgonMemory  = 256 * 1024 // 256 MB
	ArgonThreads = 4
	ArgonKeyLen  = 32
	SaltLen      = 16
	KeyLen       = 32
)

var (
	ErrDecryptionFailed = errors.New("decryption failed: authentication failed or invalid ciphertext")
)

// GenerateRandomBytes generates n cryptographically secure random bytes.
func GenerateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DeriveKey derives a key from a password and salt using Argon2id.
func DeriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305 with the given key.
// It returns a ciphertext with the nonce prepended.
func Encrypt(plaintext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce, err := GenerateRandomBytes(uint32(aead.NonceSize()))
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and append to nonce
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts a ciphertext using XChaCha20-Poly1305 with the given key.
// The ciphertext is expected to have the nonce prepended (as produced by Encrypt).
func Decrypt(ciphertext, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrDecryptionFailed
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}
