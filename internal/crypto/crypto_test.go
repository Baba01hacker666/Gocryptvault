package crypto

import (
	"bytes"
	"testing"
)

func TestCrypto(t *testing.T) {
	key, err := GenerateRandomBytes(KeyLen)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("hello vault")
	ciphertext, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("decrypted text %q does not match original %q", decrypted, plaintext)
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	b1, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("failed to generate random bytes: %v", err)
	}
	if len(b1) != 32 {
		t.Errorf("expected length 32, got %d", len(b1))
	}

	b2, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("failed to generate random bytes: %v", err)
	}

	if bytes.Equal(b1, b2) {
		t.Errorf("random bytes should not be equal")
	}
}

func TestDeriveKey(t *testing.T) {
	password := []byte("password123")
	salt := []byte("somesalt12345678")

	key1 := DeriveKey(password, salt)
	if len(key1) != ArgonKeyLen {
		t.Errorf("expected key length %d, got %d", ArgonKeyLen, len(key1))
	}

	key2 := DeriveKey(password, salt)
	if !bytes.Equal(key1, key2) {
		t.Errorf("DeriveKey should be deterministic")
	}

	key3 := DeriveKey([]byte("different"), salt)
	if bytes.Equal(key1, key3) {
		t.Errorf("DeriveKey should differ for different passwords")
	}
}

func TestDecryptInvalid(t *testing.T) {
	key, _ := GenerateRandomBytes(KeyLen)
	plaintext := []byte("secret")
	ciphertext, _ := Encrypt(plaintext, key)

	// Wrong key
	wrongKey, _ := GenerateRandomBytes(KeyLen)
	_, err := Decrypt(ciphertext, wrongKey)
	if err == nil {
		t.Errorf("expected error when decrypting with wrong key")
	}

	// Corrupted ciphertext
	ciphertext[len(ciphertext)-1] ^= 0x01
	_, err = Decrypt(ciphertext, key)
	if err == nil {
		t.Errorf("expected error when decrypting corrupted ciphertext")
	}

	// Too short ciphertext
	_, err = Decrypt([]byte("short"), key)
	if err == nil {
		t.Errorf("expected error for too short ciphertext")
	}
}
