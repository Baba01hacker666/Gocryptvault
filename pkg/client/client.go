package client

import (
	"net/rpc"
	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
	"github.com/Baba01hacker666/Gocryptvault/internal/metadata"
)

type Client struct {
	rpc *rpc.Client
}

func NewClient() (*Client, error) {
	c, err := daemon.ConnectRPC()
	if err != nil {
		return nil, err
	}
	return &Client{rpc: c}, nil
}

func (c *Client) Close() error {
	return c.rpc.Close()
}

func (c *Client) IsUnlocked() (bool, error) {
	var reply daemon.StatusReply
	err := c.rpc.Call("VaultDaemon.Status", &struct{}{}, &reply)
	if err != nil {
		return false, err
	}
	return reply.Unlocked, nil
}

func (c *Client) ListFiles() ([]*metadata.FileRecord, error) {
	var reply []*metadata.FileRecord
	err := c.rpc.Call("VaultDaemon.ListFiles", &struct{}{}, &reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (c *Client) GetFile(fileID string) (*metadata.FileRecord, error) {
	var reply metadata.FileRecord
	err := c.rpc.Call("VaultDaemon.GetFile", fileID, &reply)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}
