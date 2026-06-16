# Gocryptvault — Bug & Issue Report

Generated: 2026-06-16 | Verified: `go build ./...` passes; `go test ./...` has 4 failures

---

## BUILD FAILURES (tests won't compile)

### B1. `NewDaemon(v)` missing `timeout` argument (4 call sites)

**Files:**
- `tests/distributed_test.go:186`
- `tests/deletion_test.go:66`
- `tests/deletion_test.go:163`
- `tests/deniable_test.go:64`

**Problem:** Each calls `daemon.NewDaemon(v)` with a single `*storage.Vault` argument.
The constructor signature is:

```go
// internal/daemon/daemon.go:33
func NewDaemon(vault *storage.Vault, timeout time.Duration) *Daemon
```

The `timeout` parameter was added for configurable auto-lock but the integration tests were never updated.

**Impact:** `go test ./tests/` — build failure.

**Fix:** Add a timeout, e.g. `daemon.NewDaemon(v, 15*time.Minute)`.

---

### B2. `RunServer()` missing `timeout` argument

**File:** `tests/daemon_client_test.go:36`

```go
if err := daemon.RunServer(); err != nil {
```

**Problem:** Signature is `RunServer(timeout time.Duration) error`. One argument missing.

**Impact:** Build failure in `tests/` package.

**Fix:** `daemon.RunServer(15 * time.Minute)`.

---

## TEST FAILURES (compile but fail at runtime)

### B3. Coordinator unit tests broken by RBAC (role-based access control)

**File:** `internal/coordinator/server_test.go`

**Problem:** All coordinator server methods now call `requireRole()` → `certRole()` which does:

```go
p, ok := peer.FromContext(ctx)
if !ok { return "", fmt.Errorf("no peer in context") }
```

The test passes `context.Background()` with no gRPC peer metadata, so `certRole` always returns `"no peer in context"` and every test fails:

```
--- FAIL: TestCoordinatorServer (0.00s)
    server_test.go:30: GetMetadata failed: authorization failed: no peer in context
```

**Impact:** 0% test coverage for coordinator gRPC handlers.

**Fix:** Inject a faux gRPC peer context with a TLS certificate carrying the correct OU, or add a `--insecure`/testing bypass.

---

### B4. Node `TestStorageServer` broken by shard ID validation

**File:** `internal/node/server_test.go:52`

**Problem:** `validateShardID()` was hardened with a strict regex:

```go
var shardIDRegex = regexp.MustCompile(`^[0-9a-f]{64}$`)
```

The test uses `shardID := "test-shard-id"` (13 chars, contains hyphens) which fails:

```
--- FAIL: TestStorageServer (0.01s)
    server_test.go:65: CloseAndRecv failed: rpc error: code = Unknown
    desc = invalid shard ID format: must be 64 lowercase hex characters
```

**Fix:** Use a valid 64-char hex string in the test, e.g. `sha256hex("test-shard-id")`.

---

## FUNCTIONAL BUGS

### B5. `ExportFile` writes to `.tmp` and never renames — exports silently produce wrong filenames

**File:** `internal/storage/storage.go` — `ExportFile` method

**Problem:** The method opens a temp file `dest + ".tmp"`, writes all decrypted data to it, and returns — but **`os.Rename(tmpDest, dest)` is never called**. The FIXED comment even promises atomic rename:

```go
// FIXED HIGH-09: use 0700 for output directory, 0600 for the output file.
// ...
// Write to a temp file first; rename atomically on success so a partial
// plaintext file is never left on disk if decryption fails mid-way.
tmpDest := dest + ".tmp"
out, err := os.OpenFile(tmpDest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
// ... all the data writing ...
return nil   // <--- os.Rename(tmpDest, dest) is MISSING
```

Additionally, the deferred cleanup is dead code because `exportErr` is never assigned:

```go
var exportErr error
defer func() {
    out.Close()
    if exportErr != nil {   // exportErr is ALWAYS nil
        os.Remove(tmpDest)
    }
}()
// ... multiple `return err` (not `exportErr = err; return exportErr`)
```

**Impact:** Every local export produces a file named `<filename>.tmp` instead of `<filename>`. On failure, `.tmp` files are never cleaned up.

**Fix:** Add `os.Rename(tmpDest, dest)` before the final `return nil`, and assign errors to `exportErr` in the defer path.

---

### B6. `GetKeys` RPC removed from daemon but callers still invoke it — runtime errors

**Files:**
- `internal/daemon/client.go:39` — `EnsureLocalSession()`
- `pkg/client/distributed.go:767` — `ensureSession()`

**Problem:** Both functions call:

```go
err = client.Call("VaultDaemon.GetKeys", &struct{}{}, &reply)
```

But `GetKeys` was **removed** per security review CRIT-01:

```go
// FIXED CRIT-01: GetKeys is REMOVED. Raw key material must never leave the daemon.
// daemon/daemon.go:112
```

No `GetKeys` method exists on `*Daemon` anymore, so these RPC calls will **always fail at runtime** with `"rpc: can't find method VaultDaemon.GetKeys"`.

**Impact:**
- `cmd/list.go` → `daemon.ListFilesRPC()` → `EnsureLocalSession()` → `GetKeys` — always broken
- Every distributed method that needs `ensureSession()` (upload, download, list, delete) is broken when the CLI process doesn't already hold a local session

**Fix:** Redesign session propagation. Since keys must never leave the daemon, CLI commands that need distributed operations must proxy through the daemon rather than importing keys into the CLI process. The options are:
1. Add distributed methods to the daemon RPC so the daemon handles gRPC calls on behalf of clients
2. Generate ephemeral operation tokens instead of raw keys

---

### B7. `SaveState` stores shard locations in **plaintext** — comment claims encryption was implemented

**File:** `internal/coordinator/server.go:201-211`

**Problem:** The FIXED HIGH-06 comment describes encryption that was never actually written:

```go
// FIXED HIGH-06: SaveState encrypts shards.json using a random nonce so the
// shard-location mapping is not a plaintext metadata oracle.
// NOTE: For full security this should use the coordinator's master key derived
// from the vault password. As a stepping stone, we use a per-run random key
// stored in memory only, which at least prevents off-line reads of the file.
func (s *CoordinatorServer) SaveState() error {
    path := filepath.Join(s.VaultDir, "shards.json")
    s.Registry.mu.RLock()
    defer s.Registry.mu.RUnlock()
    data, err := json.Marshal(s.Registry.shardLocations)  // plaintext JSON
    if err != nil {
        return err
    }
    // Write with strict permissions so only the daemon user can read it.
    return os.WriteFile(path, data, 0600)  // no encryption at all
}
```

The comment says "per-run random key stored in memory only" — no such key exists, no encryption happens. The file `shards.json` on disk contains a readable mapping of `fileID → shardID → nodeID`.

**Impact:** Anyone who reads the coordinator's `shards.json` can map every file ID to every storage node hosting its shards. This is a metadata oracle that undermines the zero-trust design.

**Fix:** Either implement the described encryption (generate an ephemeral key, encrypt the JSON blob) or remove the misleading comment and document this as a known limitation.

---

### B8. Distributed mode broken by default — gRPC is disabled but all clients use gRPC

**File:** `cmd/coordinator.go:72,82`

**Problem:** The coordinator flags:

```go
coordinatorCmd.Flags().StringVar(&coordGRPCAddr, "grpc-addr", "",
    "Address to listen on for gRPC API (disabled by default, explicit separate port required)")
```

`coordGRPCAddr` defaults to `""`, so:

```go
if coordGRPCAddr != "" {
    grpcLis, _ := net.Listen("tcp", coordGRPCAddr)
    // ...
    pb.RegisterCoordinatorServer(s, server)
    go s.Serve(grpcLis)
}
```

The gRPC server never starts. Meanwhile, **all** distributed client code (`pkg/client/distributed.go`) exclusively uses gRPC:

```go
conn, err := grpc.Dial(coordinatorAddr,
    grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
```

**Impact:** Running `./gocryptvault add secret.txt --distributed` without explicitly passing `--grpc-addr` to the coordinator results in a connection error. Distributed mode is effectively dead by default.

**Fix:** Either:
- Default gRPC to the same port (multiplex gRPC + HTTP on the same listener), or
- Default `grpc-addr` to the `--addr` value, or
- Implement the REST client path so distributed operations use the HTTPS API

---

### B9. Coordinator `GetDownloadPlan` maps node ID→endpoint incorrectly

**File:** `internal/coordinator/server.go:118-131`

**Problem:**

```go
func (s *CoordinatorServer) GetDownloadPlan(...) (*pb.DownloadPlanResponse, error) {
    shardToNode := s.Registry.GetShardLocations(req.FileId)
    locs := make(map[string]string)
    for shardID, nodeID := range shardToNode {
        node := s.Registry.GetNode(nodeID)
        if node != nil {
            locs[shardID] = node.Endpoint
        } else {
            locs[shardID] = nodeID  // fallback: treat nodeID as endpoint
        }
    }
    return &pb.DownloadPlanResponse{Locations: locs}, nil
}
```

Shard locations are set during upload in `AddFileDistributed`:

```go
shardLocs.ShardToNode[shardID] = nodeEndpoint  // stores the endpoint string
```

So `GetShardLocations` returns `map[shardID]endpoint`. Then `GetNode(endpoint)` looks up the endpoint string in the node registry — but nodes are registered by their `--id` (e.g. `"node-1"`), **not** by their endpoint. `GetNode` returns `nil`, and the fallback `locs[shardID] = nodeID` passes the endpoint through directly. This happens to **work** for the download path because the client just needs the endpoint to dial — but the `GetNode` lookup is always a no-op.

**Impact:** Currently functional because the fallback path saves it. But if the shardLocations map ever stores node IDs instead of endpoints (as the field name `nodeID` suggests), this will break silently.

**Fix:** Either rename the map to reflect that it stores endpoints, or store actual node IDs and fix the upload path to pass `nodeID` instead of `nodeEndpoint`, then rely on `GetNode(nodeID).Endpoint` for resolution.

---

### B10. Node command: gRPC registration connection never closed

**File:** `cmd/node.go:43-52`

**Problem:**

```go
conn, err := grpc.Dial(nodeCoordAddr,
    grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
if err != nil {
    return fmt.Errorf("failed to connect to coordinator for registration: %w", err)
}
coord := pb.NewCoordinatorClient(conn)
_, err = coord.RegisterNode(context.Background(), &pb.NodeInfo{...})
// conn.Close() is never called
```

The gRPC connection to the coordinator is opened for registration and never closed. The GC will eventually reclaim it, but this leaks a TCP connection + TLS session for the lifetime of the node process.

**Fix:** Add `defer conn.Close()` after the error check.

---

### B11. `generateUUID` uses `math/rand` instead of `crypto/rand` — predictable file IDs

**File:** `internal/storage/storage.go`

```go
func (v *Vault) generateUUID() string {
    b := make([]byte, 16)
    rand.Read(b)  // math/rand.Read — seeded by time, predictable
    return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
```

`rand.Read` is from `math/rand` (line 4: `"crypto/rand"` imported but never used for this). This is seeded by the system clock and produces predictable output. File IDs are not secret, but deterministic IDs enable metadata correlation and make vault contents enumerable.

**Fix:** Use `crypto/rand.Read` (already imported).

---

## SECURITY CONCERNS

### S1. No rate limiting on daemon Unix socket unlock

**File:** `internal/daemon/daemon.go:Unlock`

The daemon's `Unlock` RPC accepts password attempts at wire speed over the Unix socket. With a local attacker, the 256MB Argon2id cost provides ~50ms of slowdown per attempt, but there's **no attempt counter, no cooldown, no lockout**. A process on the same machine can attempt thousands of passwords per minute.

**Fix:** Add exponential backoff or a max-attempts counter.

### S2. `cluster-status` creates empty `Client{}` — nil RPC field

**File:** `cmd/cluster_status.go:36`

```go
c := &client.Client{} // We only need the GetClusterStatus method, no RPC connection
```

If anyone later adds an RPC-dependent method and the cluster-status code path calls it (or `GetClusterStatus` is refactored to use RPC), this will produce a nil pointer dereference.

**Fix:** `GetClusterStatus` should be a standalone function that doesn't require a `Client` receiver.

### S3. Password piping reads full line with trailing newline

**File:** `cmd/password.go`

When stdin is not a terminal, the function reads a line with `bufio.Reader.ReadString('\n')`. It trims `\r\n` but a lone `\n` from a pipe like `echo "password" | ./gocryptvault init` includes the newline in the password bytes. This produces a different derived key than typing the same password interactively.

**Fix:** Trim all trailing whitespace (`strings.TrimRight(pass, "\r\n ")`) or use `strings.TrimSpace`.

---

## MISSING FEATURES / INCOMPLETE WORK

| # | Item | Detail |
|---|------|--------|
| M1 | `version` command | No way to determine binary version at runtime |
| M2 | Vault integrity check (`fsck`) | No checksum verification of shards at rest; silent corruption |
| M3 | Metadata backup/restore | If `metadata.enc` is corrupted, the entire vault is unrecoverable |
| M4 | Hidden vault (local mode) | `--hidden` flag only works with `--distributed`; local `add`/`list`/`export`/`delete` have no hidden vault support |
| M5 | FUSE unmount is a stub | `fuse.Unmount()` only works in-process; the `unmount` CLI command always hits the fallback error |
| M6 | Progress reporting | Large file uploads/downloads have no progress feedback |
| M7 | Structured logging | `fmt.Println`, `log.Printf`, `log.Fatalf` used inconsistently; no log levels |
| M8 | Configurable Argon2id | `ArgonTime=4, ArgonMemory=256MB` is hardcoded; no knob for low-memory or high-security |
| M9 | Key rotation | Changing master key requires re-encrypting every object; no migration path |
| M10 | `wipeSlice` duplication | `storage.go` defines its own `wipeSlice` identical to `memory.Wipe` |
| M11 | `--config` flag | Vault path only configurable via `GOCRYPTVAULT_PATH` env var |

---

## SUMMARY

| Severity | Count | Key Items |
|----------|-------|-----------|
| Build failure | 4 | B1, B2 (tests don't compile) |
| Test failure | 2 | B3 (coordinator RBAC), B4 (node shard ID regex) |
| Functional bug | 7 | B5 (export .tmp never renamed), B6 (GetKeys removed but called), B7 (plaintext shards.json), B8 (gRPC disabled by default), B9 (download plan node lookup), B10 (connection leak), B11 (predictable file IDs) |
| Security | 3 | S1 (no brute-force protection), S2 (nil RPC fragility), S3 (piped password newline) |
| Missing | 11 | M1-M11 |
