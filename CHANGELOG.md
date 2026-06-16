# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Architecture**: Sharded Metadata Distribution! The single `metadata.enc` bottleneck that previously limited vault scalability has been eliminated. The Coordinator now dynamically shards the vault's metadata into 16 distinct database files based on a SHA-256 hash of the File ID. When adding, exporting, or deleting files, the client only downloads and updates the exact 1MB deniable shard responsible for that file, vastly reducing network transfer and preventing Coordinator OOM crashes on massive vaults.
- **Storage/Compression**: Integrated transparent File Compression before Sharding. All file chunks are now automatically streamed through a blazing-fast DEFLATE algorithm (`flate.BestSpeed`) before being encrypted and erasure-coded. Highly compressible files (like text or JSON) will now consume radically less distributed disk space, while the engine automatically falls back to raw storage for incompressible media.
- **Storage/Placement**: Implemented Smart Capacity Placement! Storage nodes now dynamically report their real-time disk free space during their minute-by-minute heartbeats to the Coordinator. The Coordinator strictly filters out nodes that do not have adequate free space to accept a shard, and optimally routes new shards to the nodes with the most available capacity!
- **CLI**: Added `gocryptvault cluster-status` command. You can now securely query the Coordinator's HTTPS REST API to instantly view the health, active endpoint, capacity, and `LastSeen` timestamp of all active Storage Nodes in the distributed cluster.
- **Daemon**: Added configurable Auto-Lock Timeout. The vault daemon can now be started with a custom timeout (e.g. `--timeout 1h`) instead of the hardcoded 15 minutes, or disabled entirely (`--timeout 0`). This flag is available on both the `daemon` and `unlock` commands.
- **Coordinator**: Implemented automated stale node eviction. The coordinator now spins up a background goroutine that periodically sweeps the node registry and automatically removes any nodes that haven't sent a heartbeat within the last 5 minutes.

### Changed
- **Client/Network**: Dramatically accelerated distributed file downloads by implementing Multi-node Concurrent Chunk Fetching. Previously, the client fetched entire 4MB chunks sequentially, severely bottlenecking multi-gigabit connections. The export engine now spawns a fully bounded asynchronous worker pool that intelligently requests completely separate chunks from different Storage Nodes simultaneously, streaming reconstructed data into sequential channels for perfectly ordered disk writes.
- **Daemon**: Implemented Graceful Shutdown Waitgroups to prevent horrific data corruption. The daemon now utilizes a sophisticated request waitgroup pattern for all active Vault operations (like `AddFile`, `ExportFile`). If the daemon is ordered to shut down or auto-lock, it halts the acceptance of new requests, but safely waits for all inflight 2-hour multi-gigabyte exports to safely finish encrypting/decrypting before zeroing the master key out of memory.
- **Storage**: Fixed unbounded memory growth during massive file exports. The worker pool queue is now strictly bounded by a semaphore matching the concurrent CPU limit (`maxInFlight`). Out-of-order chunk processing no longer accumulates in memory while waiting for slower chunks to decrypt, preventing OOM crashes on large files.
- **FUSE / Storage**: Massive performance optimization for FUSE mount `stat` and `read` operations. The `Getattr` and `Read` operations in the FUSE filesystem were previously iterating over the entire list of files in the vault sequentially (O(N)). Introduced an O(1) `GetFile(fileID)` dictionary lookup in the `Storage` layer and exposed it through the Daemon to eliminate this severe bottleneck.

### Fixed
- **CLI / Daemon**: Fixed a critical bug in `gocryptvault delete` where local file deletion bypassed the Daemon and attempted to read from memory directly (which failed because the CLI process doesn't hold the decrypted session keys). `DeleteFileLocal` is now properly exposed over the Daemon RPC and the CLI routes deletion through the active background daemon.
