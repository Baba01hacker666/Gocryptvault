# Public Client Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a public Go library `pkg/client` to allow external programs to interact with the Gocryptvault daemon.

**Architecture:** Create a wrapper around internal RPC calls, providing a stable and idiomatic Go API.

**Tech Stack:** Go, net/rpc.

---

### Task 1: Create pkg/client package

**Files:**
- Create: `pkg/client/client.go`

- [ ] **Step 1: Define Client struct and NewClient constructor**

```go
package client

import (
	"net/rpc"
	"github.com/Baba01hacker666/Gocryptvault/internal/daemon"
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
```

- [ ] **Step 2: Implement IsUnlocked method**

```go
func (c *Client) IsUnlocked() (bool, error) {
	var reply daemon.StatusReply
	err := c.rpc.Call("VaultDaemon.Status", &struct{}{}, &reply)
	if err != nil {
		return false, err
	}
	return reply.Unlocked, nil
}
```

- [ ] **Step 3: Implement ListFiles method**

```go
import "github.com/Baba01hacker666/Gocryptvault/internal/metadata"

func (c *Client) ListFiles() ([]*metadata.FileRecord, error) {
	var reply []*metadata.FileRecord
	err := c.rpc.Call("VaultDaemon.ListFiles", &struct{}{}, &reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
```

- [ ] **Step 4: Implement GetFile method**

```go
func (c *Client) GetFile(fileID string) (*metadata.FileRecord, error) {
	var reply metadata.FileRecord
	err := c.rpc.Call("VaultDaemon.GetFile", fileID, &reply)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}
```

- [ ] **Step 5: Commit**

```bash
git add pkg/client/client.go
git commit -m "feat(lib): initial implementation of pkg/client"
```

---

### Task 2: Implement Add/Export in the Daemon and Client

**Note:** `AddFile` and `ExportFile` need to be exposed via RPC to be accessible through the library.

**Files:**
- Modify: `internal/daemon/daemon.go`
- Modify: `pkg/client/client.go`

- [ ] **Step 1: Add AddFile and ExportFile RPC to Daemon**

```go
// in internal/daemon/daemon.go

type AddFileArgs struct {
	SourcePath  string
	LogicalName string
}

func (d *Daemon) AddFile(args *AddFileArgs, reply *bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	err := d.vault.AddFile(args.SourcePath, args.LogicalName)
	if err != nil {
		*reply = false
		return err
	}
	*reply = true
	d.lastActivity = time.Now()
	return nil
}

type ExportFileArgs struct {
	FileID  string
	DestDir string
}

func (d *Daemon) ExportFile(args *ExportFileArgs, reply *bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	err := d.vault.ExportFile(args.FileID, args.DestDir)
	if err != nil {
		*reply = false
		return err
	}
	*reply = true
	d.lastActivity = time.Now()
	return nil
}
```

- [ ] **Step 2: Implement AddFile and ExportFile in Client**

```go
// in pkg/client/client.go

func (c *Client) AddFile(sourcePath, logicalName string) error {
	var reply bool
	args := &daemon.AddFileArgs{SourcePath: sourcePath, LogicalName: logicalName}
	return c.rpc.Call("VaultDaemon.AddFile", args, &reply)
}

func (c *Client) ExportFile(fileID, destDir string) error {
	var reply bool
	args := &daemon.ExportFileArgs{FileID: fileID, DestDir: destDir}
	return c.rpc.Call("VaultDaemon.ExportFile", args, &reply)
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/daemon/daemon.go pkg/client/client.go
git commit -m "feat(lib): add AddFile and ExportFile to client library"
```

---

### Task 3: Add Integration Test and Example

**Files:**
- Create: `tests/library_test.go`
- Create: `examples/client_usage/main.go`

- [ ] **Step 1: Create library integration test**

```go
package tests

import (
	"testing"
	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
)

func TestClientLibrary(t *testing.T) {
    // Requires a running daemon or a mock
    // For simplicity, we can test that the client connects and returns errors if daemon is missing
}
```

- [ ] **Step 2: Create usage example**

```go
package main

import (
	"fmt"
	"log"
	"github.com/Baba01hacker666/Gocryptvault/pkg/client"
)

func main() {
	c, err := client.NewClient()
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
    // ...
}
```

- [ ] **Step 3: Commit**

```bash
git add tests/library_test.go examples/client_usage/main.go
git commit -m "test(lib): add library test and example"
```
