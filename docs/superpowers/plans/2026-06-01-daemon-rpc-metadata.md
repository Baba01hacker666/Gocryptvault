# Implement Daemon RPC for Metadata Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `ListFiles` and `GetFile` RPC methods in the daemon to allow querying metadata via the persistent daemon session.

**Architecture:** Extend the `Daemon` struct in `internal/daemon/daemon.go` with two new exported methods that leverage the `Vault.ListFiles()` method (which includes caching logic). These methods will be exposed via the existing UNIX socket RPC server.

**Tech Stack:** Go (Standard Library `net/rpc`).

---

### Task 1: Add ListFiles RPC

**Files:**
- Modify: `internal/daemon/daemon.go`

- [ ] **Step 1: Implement ListFiles method**

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

- [ ] **Step 2: Verify compilation**

Run: `go build ./internal/daemon/...`
Expected: Success

- [ ] **Step 3: Commit changes**

```bash
git add internal/daemon/daemon.go
git commit -m "feat(daemon): add ListFiles RPC method"
```

### Task 2: Add GetFile RPC

**Files:**
- Modify: `internal/daemon/daemon.go`

- [ ] **Step 1: Implement GetFile method**

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

- [ ] **Step 2: Verify compilation**

Run: `go build ./internal/daemon/...`
Expected: Success

- [ ] **Step 3: Commit changes**

```bash
git add internal/daemon/daemon.go
git commit -m "feat(daemon): add GetFile RPC method"
```
