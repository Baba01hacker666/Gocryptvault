# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Daemon**: Added configurable Auto-Lock Timeout. The vault daemon can now be started with a custom timeout (e.g. `--timeout 1h`) instead of the hardcoded 15 minutes, or disabled entirely (`--timeout 0`). This flag is available on both the `daemon` and `unlock` commands.
- **Coordinator**: Implemented automated stale node eviction. The coordinator now spins up a background goroutine that periodically sweeps the node registry and automatically removes any nodes that haven't sent a heartbeat within the last 5 minutes.

### Changed
- **FUSE / Storage**: Massive performance optimization for FUSE mount `stat` and `read` operations. The `Getattr` and `Read` operations in the FUSE filesystem were previously iterating over the entire list of files in the vault sequentially (O(N)). Introduced an O(1) `GetFile(fileID)` dictionary lookup in the `Storage` layer and exposed it through the Daemon to eliminate this severe bottleneck.

### Fixed
- **CLI / Daemon**: Fixed a critical bug in `gocryptvault delete` where local file deletion bypassed the Daemon and attempted to read from memory directly (which failed because the CLI process doesn't hold the decrypted session keys). `DeleteFileLocal` is now properly exposed over the Daemon RPC and the CLI routes deletion through the active background daemon.
