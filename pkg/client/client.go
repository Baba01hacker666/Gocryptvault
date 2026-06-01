package client

import (
	"fmt"
	"net/rpc"

	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/Baba01hacker666/Gocryptvault/pkg/types"
)

type Client struct {
	RPC *rpc.Client
}

func NewClient() (*Client, error) {
	c, err := daemon.ConnectRPC()
	if err != nil {
		return nil, fmt.Errorf("client: failed to connect to daemon: %w", err)
	}
	return &Client{RPC: c}, nil
}

func (c *Client) Close() error {
	return c.RPC.Close()
}

func (c *Client) Unlock(password []byte) (bool, error) {
	var reply bool
	err := c.RPC.Call("VaultDaemon.Unlock", password, &reply)
	if err != nil {
		return false, fmt.Errorf("client: failed to unlock: %w", err)
	}
	return reply, nil
}

func (c *Client) GetSalt() ([]byte, error) {
	var salt []byte
	err := c.RPC.Call("VaultDaemon.GetSalt", &struct{}{}, &salt)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get salt: %w", err)
	}
	return salt, nil
}

func (c *Client) IsUnlocked() (bool, error) {
	var reply types.StatusReply
	err := c.RPC.Call("VaultDaemon.Status", &struct{}{}, &reply)
	if err != nil {
		return false, fmt.Errorf("client: failed to get status: %w", err)
	}
	return reply.Unlocked, nil
}

func (c *Client) ListFiles() ([]*types.FileRecord, error) {
	var reply []*types.FileRecord
	err := c.RPC.Call("VaultDaemon.ListFiles", &struct{}{}, &reply)
	if err != nil {
		return nil, fmt.Errorf("client: failed to list files: %w", err)
	}
	return reply, nil
}

func (c *Client) GetFile(fileID string) (*types.FileRecord, error) {
	var reply types.FileRecord
	err := c.RPC.Call("VaultDaemon.GetFile", fileID, &reply)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get file: %w", err)
	}
	return &reply, nil
}

func (c *Client) AddFile(sourcePath, logicalName string) error {
	var reply bool
	args := &types.AddFileArgs{SourcePath: sourcePath, LogicalName: logicalName}
	if err := c.RPC.Call("VaultDaemon.AddFile", args, &reply); err != nil {
		return fmt.Errorf("client: failed to add file: %w", err)
	}
	return nil
}

func (c *Client) ExportFile(fileID, destDir string) error {
	var reply bool
	args := &types.ExportFileArgs{FileID: fileID, DestDir: destDir}
	if err := c.RPC.Call("VaultDaemon.ExportFile", args, &reply); err != nil {
		return fmt.Errorf("client: failed to export file: %w", err)
	}
	return nil
}

