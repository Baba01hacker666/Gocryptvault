# Design Spec: Public Client Library (pkg/client)

## 1. Goal
Expose Gocryptvault's functionality as a stable Go library that other developers can import. The library will focus on interacting with a running `vaultfs` daemon, allowing third-party applications to store and retrieve encrypted files without managing the low-level crypto themselves.

## 2. Approach
Create a new public package `pkg/client` that provides a clean, idiomatic Go API. This package will wrap the internal RPC logic currently found in `internal/daemon`.

## 3. Public API Surface

The primary entry point will be a `Client` struct:

```go
package client

import "github.com/Baba01hacker666/Gocryptvault/internal/metadata"

type Client struct {
    // contains filtered or hidden fields
}

// NewClient creates a new daemon client.
func NewClient() (*Client, error)

// IsUnlocked checks if the vault is currently unlocked in the daemon.
func (c *Client) IsUnlocked() (bool, error)

// ListFiles returns a list of all files in the vault.
func (c *Client) ListFiles() ([]*metadata.FileRecord, error)

// GetFile returns metadata for a specific file.
func (c *Client) GetFile(fileID string) (*metadata.FileRecord, error)

// AddFile adds a local file to the vault via the daemon's storage context.
func (c *Client) AddFile(sourcePath, logicalName string) error

// ExportFile exports a file from the vault to a local path.
func (c *Client) ExportFile(fileID, destDir string) error

// Close closes the connection to the daemon.
func (c *Client) Close() error
```

## 4. Implementation Details

- **Package Path**: `pkg/client`
- **Dependencies**: Uses `internal/daemon` for the underlying RPC calls and `internal/metadata` for types.
- **Error Handling**: Wraps internal RPC errors into user-friendly library errors.
- **Convenience**: Handles socket path discovery automatically using `internal/config`.

## 5. Usage Example

```go
import "github.com/Baba01hacker666/Gocryptvault/pkg/client"

c, _ := client.NewClient()
defer c.Close()

if unlocked, _ := c.IsUnlocked(); unlocked {
    files, _ := c.ListFiles()
    for _, f := range files {
        fmt.Println(f.Filename)
    }
}
```

## 6. Security Considerations
- The client only works if the daemon is running and the vault is already unlocked (or if the client has permission to unlock).
- Access is restricted by the UNIX socket permissions (0600).
