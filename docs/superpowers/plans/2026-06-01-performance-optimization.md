# Performance Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve vault performance by implementing daemon-side metadata caching.

**Architecture:** Add thread-safe caching to `storage.Vault` validated by file `ModTime`, and expose via RPC for CLI commands.

**Tech Stack:** Go, net/rpc, sync.RWMutex.

---

### Task 1: Add Cache Fields to storage.Vault

**Files:**
- Modify: `internal/storage/storage.go`

- [ ] **Step 1: Add mutex and cache fields to Vault struct**

```go
type Vault struct {
	BaseDir      string
	mu           sync.RWMutex
	metaCache    *metadata.MetadataDB
	cacheModTime time.Time
}

func NewVault(baseDir string) *storage.Vault {
	return &storage.Vault{
		BaseDir: baseDir,
	}
}
```

- [ ] **Step 2: Add getMetadata helper method**

```go
func (v *Vault) getMetadata() (*metadata.MetadataDB, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	sess, err := session.GetSession()
	if err != nil {
		return nil, err
	}

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

	db, err := metadata.LoadEncryptedMetadata(metaPath, sess.GetMetaKey())
	if err != nil {
		return nil, err
	}

	v.metaCache = db
	v.cacheModTime = info.ModTime()
	return db, nil
}
```

- [ ] **Step 3: Update ListFiles to use getMetadata**

```go
func (v *Vault) ListFiles() ([]*metadata.FileRecord, error) {
	db, err := v.getMetadata()
	if err != nil {
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	var files []*metadata.FileRecord
	for _, f := range db.Files {
		files = append(files, f)
	}

	return files, nil
}
```

- [ ] **Step 4: Update AddFile and DeleteFile to invalidate/update cache**

In `AddFile`, after saving metadata:
```go
	err = metadata.SaveEncryptedMetadata(metaPath, db, sess.GetMetaKey())
	if err == nil {
		// Update cache info
		if info, err := os.Stat(metaPath); err == nil {
			v.mu.Lock()
			v.cacheModTime = info.ModTime()
			v.mu.Unlock()
		}
	}
	return err
```

- [ ] **Step 5: Run existing tests**

Run: `go test ./internal/storage -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/storage/storage.go
git commit -m "refactor(storage): add metadata caching to Vault"
```

---

### Task 2: Implement Daemon RPC for Metadata

**Files:**
- Modify: `internal/daemon/daemon.go`

- [ ] **Step 1: Add ListFiles RPC to Daemon struct**

```go
func (d *Daemon) ListFiles(req *struct{}, reply *[]*metadata.FileRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	files, err := d.vault.ListFiles()
	if err != nil {
		return err
	}

	*reply = files
	d.lastActivity = time.Now()
	return nil
}
```

- [ ] **Step 2: Add GetFile RPC to Daemon struct**

```go
func (d *Daemon) GetFile(fileID string, reply *metadata.FileRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	files, err := d.vault.ListFiles()
	if err != nil {
		return err
	}

	for _, f := range files {
		if f.ID == fileID {
			*reply = *f
			d.lastActivity = time.Now()
			return nil
		}
	}

	return fmt.Errorf("file not found")
}
```

- [ ] **Step 3: Commit**

```bash
git add internal/daemon/daemon.go
git commit -m "feat(daemon): add ListFiles and GetFile RPC methods"
```

---

### Task 3: Add Client Helper and Update cmd/list

**Files:**
- Modify: `internal/daemon/client.go`
- Modify: `cmd/list.go`

- [ ] **Step 1: Add ListFilesRPC to client.go**

```go
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
```

- [ ] **Step 2: Update cmd/list.go to use RPC first**

```go
	RunE: func(cmd *cobra.Command, args []string) error {
		// Try RPC first
		files, err := daemon.ListFilesRPC()
		if err != nil {
			// Fallback to local
			v := getVault()
			files, err = v.ListFiles()
			if err != nil {
				return fmt.Errorf("failed to list files: %w", err)
			}
		}
...
```

- [ ] **Step 3: Commit**

```bash
git add internal/daemon/client.go cmd/list.go
git commit -m "feat(cli): use daemon RPC for listing files"
```

---

### Task 4: Verify Cache Efficiency

**Files:**
- Create: `tests/performance_test.go`

- [ ] **Step 1: Write a test that measures ListFiles timing**

```go
func TestMetadataCacheEffect(t *testing.T) {
    // 1. Setup vault with 100 dummy files
    // 2. Measure first ListFiles (cold)
    // 3. Measure second ListFiles (warm)
    // 4. Assert second is significantly faster
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./tests/performance_test.go -v`
Expected: PASS and output shows speedup.

- [ ] **Step 3: Commit**

```bash
git add tests/performance_test.go
git commit -m "test: add performance test for metadata cache"
```
