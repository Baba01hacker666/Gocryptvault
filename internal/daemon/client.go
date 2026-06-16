package daemon

import (
	"fmt"

	"github.com/Baba01hacker666/Gocryptvault/internal/session"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
)

func ListFilesRPC() ([]*types.FileRecord, error) {
	client, err := ConnectRPC()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	var reply []*types.FileRecord
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

	var reply types.KeysReply
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

func AddFileDistributedRPC(args *types.DistAddArgs) error {
	client, err := ConnectRPC()
	if err != nil { return err }
	defer client.Close()

	var reply bool
	err = client.Call("VaultDaemon.AddFileDistributed", args, &reply)
	if err != nil { return err }
	if !reply { return fmt.Errorf("daemon returned false") }
	return nil
}

func ExportFileDistributedRPC(args *types.DistExportArgs) error {
	client, err := ConnectRPC()
	if err != nil { return err }
	defer client.Close()

	var reply bool
	err = client.Call("VaultDaemon.ExportFileDistributed", args, &reply)
	if err != nil { return err }
	if !reply { return fmt.Errorf("daemon returned false") }
	return nil
}

func ListFilesDistributedRPC(args *types.DistListArgs) ([]*types.FileRecord, error) {
	client, err := ConnectRPC()
	if err != nil { return nil, err }
	defer client.Close()

	var reply []*types.FileRecord
	err = client.Call("VaultDaemon.ListFilesDistributed", args, &reply)
	if err != nil { return nil, err }
	return reply, nil
}

func DeleteFileDistributedRPC(args *types.DistDeleteArgs) error {
	client, err := ConnectRPC()
	if err != nil { return err }
	defer client.Close()

	var reply bool
	err = client.Call("VaultDaemon.DeleteFileDistributed", args, &reply)
	if err != nil { return err }
	if !reply { return fmt.Errorf("daemon returned false") }
	return nil
}
