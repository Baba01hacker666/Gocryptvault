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
