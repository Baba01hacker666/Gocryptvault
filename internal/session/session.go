package session

import (
	"errors"
	"sync"
	"time"

	"vaultfs/internal/memory"
)

var (
	ErrNotUnlocked = errors.New("vault is locked")
)

type Session struct {
	MasterKey *memory.SecureSlice
	MetaKey   *memory.SecureSlice
	LastUsed  time.Time
	mu        sync.RWMutex
}

var globalSession *Session
var sessionMutex sync.RWMutex

func InitSession(masterKey, metaKey []byte) error {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	if globalSession != nil {
		globalSession.Destroy()
	}

	mk, err := memory.NewSecureSlice(len(masterKey))
	if err != nil {
		return err
	}
	copy(mk.Data, masterKey)

	mek, err := memory.NewSecureSlice(len(metaKey))
	if err != nil {
		mk.Destroy()
		return err
	}
	copy(mek.Data, metaKey)

	globalSession = &Session{
		MasterKey: mk,
		MetaKey:   mek,
		LastUsed:  time.Now(),
	}

	return nil
}

func GetSession() (*Session, error) {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()

	if globalSession == nil {
		return nil, ErrNotUnlocked
	}

	globalSession.mu.Lock()
	globalSession.LastUsed = time.Now()
	globalSession.mu.Unlock()

	return globalSession, nil
}

func DestroySession() {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()

	if globalSession != nil {
		globalSession.Destroy()
		globalSession = nil
	}
}

func (s *Session) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.MasterKey != nil {
		s.MasterKey.Destroy()
	}
	if s.MetaKey != nil {
		s.MetaKey.Destroy()
	}
}

func (s *Session) GetMasterKey() []byte {
	return s.MasterKey.Data
}

func (s *Session) GetMetaKey() []byte {
	return s.MetaKey.Data
}
