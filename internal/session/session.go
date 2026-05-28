package session

import (
	"errors"
	"sync"
	"time"

	"github.com/Baba01hacker666/Gocryptvault/internal/memory"
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

func IsUnlocked() bool {
	sessionMutex.RLock()
	defer sessionMutex.RUnlock()
	return globalSession != nil
}

// GetSessionLocal gets the session strictly from the local memory without RPC
func GetSessionLocal() (*Session, error) {
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

// GetSession returns the current session. If it's missing, it should technically try to fetch it from daemon via RPC if imported in cmds.
// To avoid circular dependency with daemon, the actual logic for GetSession falling back to daemon will be handled in the daemon package itself or wrapper, but for simplicity we modify GetSession directly if we put the fallback logic in a higher level or move daemon client to another package. Let's just keep GetSession simple and add a way to set it from the daemon client.
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
