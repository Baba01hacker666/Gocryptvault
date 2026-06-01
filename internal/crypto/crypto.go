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

// DeriveHiddenKey derives a separate key for hidden metadata from a password and salt.
// It uses the same password but appends a fixed "hidden" label to the salt.
func DeriveHiddenKey(password []byte, salt []byte) []byte {
	hiddenSalt := make([]byte, len(salt)+6)
	copy(hiddenSalt, salt)
	copy(hiddenSalt[len(salt):], "hidden")
	return argon2.IDKey(password, hiddenSalt, ArgonTime, ArgonMemory, ArgonThreads, ArgonKeyLen)
}

// DeriveHiddenOffset derives a secret offset for hidden metadata from a password and salt.
// It ensures the offset is within the second half of the 1MB metadata blob.
func DeriveHiddenOffset(password []byte, salt []byte) int {
	offsetSalt := make([]byte, len(salt)+6)
	copy(offsetSalt, salt)
	copy(offsetSalt[len(salt):], "offset")
	// Use Argon2 to get 4 bytes for the offset
	hash := argon2.IDKey(password, offsetSalt, 1, 64*1024, 1, 4)
	val := uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3])

	// Ensure offset is in a reasonable range (e.g., 512KB to 900KB)
	// metadata blob is 1MB.
	minOffset := 1024 * 512 // 512 KB
	maxOffset := 1024 * 900 // 900 KB
	return minOffset + int(val%uint32(maxOffset-minOffset))
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
