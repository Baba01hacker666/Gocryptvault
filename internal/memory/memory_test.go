package memory

import (
	"bytes"
	"testing"
)

func TestWipe(t *testing.T) {
	data := []byte("secretdata")
	Wipe(data)
	if !bytes.Equal(data, make([]byte, 10)) {
		t.Errorf("Wipe failed, expected all zeros, got %v", data)
	}

	// Test empty slice
	Wipe(nil)
	empty := []byte{}
	Wipe(empty)
}

func TestSecureSlice(t *testing.T) {
	s, err := NewSecureSlice(16)
	if err != nil {
		t.Fatalf("failed to create secure slice: %v", err)
	}

	if len(s.Data) != 16 {
		t.Errorf("expected length 16, got %d", len(s.Data))
	}

	// Fill with data
	copy(s.Data, []byte("0123456789abcdef"))

	err = s.Destroy()
	if err != nil {
		t.Errorf("Destroy failed: %v", err)
	}

	if s.Data != nil {
		t.Errorf("expected Data to be nil after Destroy")
	}
}

func TestLockUnlock(t *testing.T) {
	data := []byte("test")
	err := Lock(data)
	if err != nil {
		t.Logf("Lock failed (might be permissions): %v", err)
	}

	err = Unlock(data)
	if err != nil {
		t.Logf("Unlock failed: %v", err)
	}

	// Test empty slice
	Lock(nil)
	Unlock(nil)
}
