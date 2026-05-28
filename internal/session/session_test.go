package session

import (
	"bytes"
	"github.com/Baba01hacker666/Gocryptvault/internal/crypto"
	"testing"
)

func TestInitGetDestroySession(t *testing.T) {
	// 1. GetSession when not unlocked
	DestroySession() // Ensure clean state
	_, err := GetSession()
	if err != ErrNotUnlocked {
		t.Fatalf("expected ErrNotUnlocked, got %v", err)
	}

	// 2. InitSession
	masterKey, _ := crypto.GenerateRandomBytes(crypto.KeyLen)
	metaKey, _ := crypto.GenerateRandomBytes(crypto.KeyLen)

	err = InitSession(masterKey, metaKey)
	if err != nil {
		t.Fatalf("InitSession failed: %v", err)
	}

	// 3. GetSession
	sess, err := GetSession()
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}

	if !bytes.Equal(sess.GetMasterKey(), masterKey) {
		t.Errorf("master key mismatch")
	}

	if !bytes.Equal(sess.GetMetaKey(), metaKey) {
		t.Errorf("meta key mismatch")
	}

	// 4. InitSession again (should destroy old one)
	newMasterKey, _ := crypto.GenerateRandomBytes(crypto.KeyLen)
	err = InitSession(newMasterKey, metaKey)
	if err != nil {
		t.Fatalf("second InitSession failed: %v", err)
	}

	sess, _ = GetSession()
	if !bytes.Equal(sess.GetMasterKey(), newMasterKey) {
		t.Errorf("expected new master key")
	}

	// 5. DestroySession
	DestroySession()
	_, err = GetSession()
	if err != ErrNotUnlocked {
		t.Errorf("expected ErrNotUnlocked after DestroySession")
	}
}
