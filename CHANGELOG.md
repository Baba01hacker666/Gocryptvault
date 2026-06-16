# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- **Coordinator**: Implemented automated stale node eviction. The coordinator now spins up a background goroutine that periodically sweeps the node registry and automatically removes any nodes that haven't sent a heartbeat within the last 5 minutes.
