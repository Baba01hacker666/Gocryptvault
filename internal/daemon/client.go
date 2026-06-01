package daemon

import (
	"fmt"

	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
	"github.com/Baba01hacker666/Gocryptvault/internal/session"
)

func ListFilesRPC() ([]*metadata.FileRecord, error) {
	client, err := ConnectRPC()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var reply []*metadata.FileRecord
	err = client.Call("VaultDaemon.ListFiles", &struct{}{}, &reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func EnsureLocalSession() error {
	// Try local first
	if session.IsUnlocked() {
		return nil
	}

	// Fallback to daemon
	client, err := ConnectRPC()
	if err != nil {
		return fmt.Errorf("vault is locked and daemon is not running")
	}
	defer client.Close()

	var reply KeysReply
	err = client.Call("VaultDaemon.GetKeys", &struct{}{}, &reply)
	if err != nil {
		return fmt.Errorf("vault is locked or failed to get keys from daemon: %w", err)
	}

	err = session.InitSession(reply.MasterKey, reply.MetaKey)
	if err != nil {
		return fmt.Errorf("failed to init local session: %w", err)
	}

	return nil
}
