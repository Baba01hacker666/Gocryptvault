package memory

import (
	"crypto/subtle"
	"golang.org/x/sys/unix"
)

// Wipe securely zeros out a byte slice to prevent secrets from lingering in memory.
func Wipe(b []byte) {
	if len(b) == 0 {
		return
	}
	// Use subtle to prevent compiler optimization of the wipe
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}

// Lock pins a byte slice in memory to prevent it from being swapped to disk.
func Lock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Mlock(b)
}

// Unlock unpins a byte slice in memory.
func Unlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return unix.Munlock(b)
}

// SecureSlice represents a slice of bytes that is locked in memory and
// wiped and unlocked when destroyed.
type SecureSlice struct {
	Data []byte
}

// NewSecureSlice creates a new SecureSlice of the given size.
func NewSecureSlice(size int) (*SecureSlice, error) {
	b := make([]byte, size)
	if err := Lock(b); err != nil {
		return nil, err
	}
	return &SecureSlice{Data: b}, nil
}

// Destroy wipes and unlocks the memory.
func (s *SecureSlice) Destroy() error {
	Wipe(s.Data)
	err := Unlock(s.Data)
	s.Data = nil
	return err
}
