# vaultfs

A production-grade encrypted file vault system in Go.

## Features

- **Encrypted at Rest:** All files are stored encrypted on disk.
- **Strong Cryptography:** Uses Argon2id for key derivation and XChaCha20-Poly1305 for AEAD.
- **Zero Plaintext:** Filenames and metadata are encrypted; file contents are split into chunks, encrypted, and stored via SHA-256 identifiers.
- **Secure Memory:** Uses `mlock` and secure wiping of sensitive memory segments.

## Build

```sh
CGO_ENABLED=0 go build -ldflags="-s -w" -o vaultfs main.go
```

## Usage

```sh
# Initialize the vault
vaultfs init

# Unlock the vault (prompts for password and derives in-memory session keys)
vaultfs unlock

# Add a file
vaultfs add secret.pdf

# List files
vaultfs list

# Export a file
vaultfs export <file_id> ./output/

# Delete a file
vaultfs delete <file_id>

# Lock the vault (wipes memory keys)
vaultfs lock

# Change master password
vaultfs change-password
```

## Security

Please note that you should mount or run `vaultfs unlock` before performing add/list/export commands within the current process lifetime (or adapt for daemon/fuse scenarios). Memory lock limits (ulimit) must be sufficient for `mlock` to work without dropping privileges.
