# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Daemon**: Added configurable Auto-Lock Timeout. The vault daemon can now be started with a custom timeout (e.g. `--timeout 1h`) instead of the hardcoded 15 minutes, or disabled entirely (`--timeout 0`). This flag is available on both the `daemon` and `unlock` commands.
- **Coordinator**: Implemented automated stale node eviction. The coordinator now spins up a background goroutine that periodically sweeps the node registry and automatically removes any nodes that haven't sent a heartbeat within the last 5 minutes.
