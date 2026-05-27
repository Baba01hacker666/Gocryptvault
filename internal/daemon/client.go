package daemon

import (
	"fmt"

	"vaultfs/internal/session"
)

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
