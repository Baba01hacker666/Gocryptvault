# Gocryptvault

A production-grade, distributed, and deniable encrypted file vault system written in Go.

## Features

- **Encrypted at Rest:** All files, filenames, and metadata are stored fully encrypted using XChaCha20-Poly1305.
- **Strong Cryptography:** Uses Argon2id for key derivation.
- **Zero Plaintext:** File contents are split into chunks, encrypted, and stored via SHA-256 identifiers.
- **Secure Memory:** Uses `mlock`, disables core dumps, and employs secure wiping of sensitive memory segments to prevent key leakage.
- **Background Daemon:** Runs as a secure background daemon (`gocryptvault daemon`) communicating via UNIX sockets.
- **FUSE Mount:** Mount the vault as a virtual filesystem (`gocryptvault mount`) to interact with your encrypted files natively.
- **Distributed Storage:** Run a central Coordinator and multiple Storage Nodes to distribute file shards across a network via gRPC.
- **Fault Tolerance:** Uses Reed-Solomon Erasure Coding (4 Data + 2 Parity) allowing data recovery even if 2 out of 6 storage nodes fail.
- **Zero-Trust Network:** All distributed communication is strictly authenticated and encrypted via mutual TLS (mTLS).
- **Deniable Vault:** Mathematically unprovable hidden vaults concealed within the random padding of a fixed-size metadata blob.
- **Public Client Library:** Exported `pkg/client` allowing developers to seamlessly integrate Gocryptvault's capabilities into their own Go applications.

## Build

```sh
# Requires Go
go build -o gocryptvault .
```

## Quick Start (Local Mode)

```sh
# Initialize the vault
./gocryptvault init

# Unlock and start the background daemon
./gocryptvault unlock

# Add a file
./gocryptvault add secret.txt

# List files
./gocryptvault list

# Export a file
./gocryptvault export <file_id> ./output/

# Mount via FUSE (Linux/macOS)
./gocryptvault mount ./my-mountpoint

# Lock the vault (wipes memory keys and stops daemon)
./gocryptvault lock
```

## Distributed Mode

Gocryptvault can distribute file shards across multiple servers for high availability.

1. **Start Coordinator:**
   ```sh
   ./gocryptvault coordinator --addr 0.0.0.0:50051 --ca ca.crt --cert server.crt --key server.key
   ```
2. **Start Storage Nodes:**
   ```sh
   ./gocryptvault node --addr 0.0.0.0:50052 --data-dir ./node1 --register --coordinator 127.0.0.1:50051 --id node-1 --ca ca.crt --cert node.crt --key node.key
   ```
3. **Use Distributed CLI:**
   ```sh
   ./gocryptvault add secret.txt --distributed --coordinator 127.0.0.1:50051 --ca ca.crt --cert client.crt --key client.key
   ```

## Deniable Vault

Protect your most sensitive data under duress.

```sh
# Add data to the hidden vault
./gocryptvault add top-secret.txt --distributed --hidden --hidden-password "my-secret-pass"

# List only hidden files
./gocryptvault list --distributed --hidden --hidden-password "my-secret-pass"
```

## Security Limits

Please note that memory lock limits (`ulimit -l`) must be sufficient for `mlock` to work without dropping privileges.
