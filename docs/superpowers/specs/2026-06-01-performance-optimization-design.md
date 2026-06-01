# Design Spec: Performance Optimization via Daemon-Side Metadata Caching

## 1. Problem Statement
Currently, every metadata operation (listing files, FUSE browsing, adding/deleting files) requires reading, decrypting, and unmarshaling the entire `metadata.enc` file. For large vaults, this causes significant latency. CLI commands like `list` are particularly affected as they are short-lived and cannot benefit from in-process caching.

## 2. Proposed Solution
Implement a two-layered caching system:
1.  **In-Process Cache**: The `storage.Vault` struct will maintain an in-memory `MetadataDB` cache, validated by the underlying file's `ModTime`.
2.  **Daemon RPC**: The persistent background daemon will serve as the primary cache holder and expose metadata via RPC to short-lived CLI processes.

## 3. Architecture Changes

### 3.1 `internal/storage/Vault`
- Add `mu sync.RWMutex` for thread-safe cache access.
- Add `metaCache *metadata.MetadataDB`.
- Add `cacheModTime time.Time` to track the disk file version.
- Add `loadMetadata()` internal method:
    - Checks if `metadata.enc` exists and its `ModTime`.
    - If `ModTime` matches `cacheModTime` and `metaCache` is not nil, return `metaCache`.
    - Otherwise, load from disk, update `metaCache` and `cacheModTime`.

### 3.2 `internal/daemon/Daemon`
- Implement `ListFiles(req *struct{}, reply *[]*metadata.FileRecord)` RPC.
- Implement `GetFile(fileID string, reply *metadata.FileRecord)` RPC.
- Ensure the `Daemon`'s `Vault` instance persists across connections.

### 3.3 CLI Integration (`cmd/`)
- `cmd/list`: Call `daemon.ListFilesRPC()` if available.
- `cmd/status`: Show cache status (optional).

### 3.4 FUSE Integration (`internal/fuse/`)
- The FUSE server should use the daemon's persistent `Vault` instance to benefit from the cache during browsing (`Readdir`, `Lookup`, `Getattr`).

## 4. Implementation Details

### Cache Validation
```go
func (v *Vault) getMetadata() (*metadata.MetadataDB, error) {
    v.mu.Lock()
    defer v.mu.Unlock()

    metaPath := filepath.Join(v.BaseDir, "metadata.enc")
    info, err := os.Stat(metaPath)
    if err != nil {
        if os.IsNotExist(err) {
            v.metaCache = metadata.NewMetadataDB()
            return v.metaCache, nil
        }
        return nil, err
    }

    if v.metaCache != nil && info.ModTime().Equal(v.cacheModTime) {
        return v.metaCache, nil
    }

    // Load from disk...
    db, err := metadata.LoadEncryptedMetadata(metaPath, sess.GetMetaKey())
    v.metaCache = db
    v.cacheModTime = info.ModTime()
    return db, nil
}
```

### 5. Success Criteria
- `vaultfs list` should be near-instant when the daemon is running.
- FUSE directory navigation should not cause repeated disk I/O and decryption for metadata.
- Unit tests confirm cache consistency after adding/deleting files.

## 6. Security Considerations
- The cache remains in the daemon's process memory, which is protected by existing `mlock` and secure memory wiping practices.
- RPC communication is restricted to the owner (UNIX socket `0600`).
