Full Go Encrypted Vault System — Engineering Prompt

Build a production-grade encrypted file vault system in Go.

The system must behave like a secure encrypted storage layer that:

Stores all files encrypted at rest.

Requires a password to unlock access.

Prevents plaintext storage on disk.

Uses authenticated encryption.

Uses strong password-based key derivation.

Supports adding, reading, listing, exporting, deleting files.

Supports virtual mount/unmount behavior.

Uses chunked encrypted storage.

Encrypts metadata and filenames.

Supports Linux.

Uses secure coding practices.

Uses modern cryptography only.


The implementation should be large-scale and modular.

Target output size:

1000+ lines of Go code.

Split across multiple files and packages.

Include comments.

Include tests.

Include CLI.

Include config handling.

Include logging.

Include secure memory handling where possible.



---

Project Name

vaultfs


---

Main Features

Initialization

Command:

vaultfs init

Behavior:

Ask user for password.

Generate random salt.

Derive master key using Argon2id.

Generate:

master encryption key

metadata key

filename encryption key


Create vault structure.

Store encrypted config.

Never store plaintext password.



---

Unlock

Command:

vaultfs unlock

Behavior:

Prompt password.

Derive key.

Validate authentication tag.

Mount virtual filesystem.

Create runtime session.

Keep master keys only in memory.



---

Lock

Command:

vaultfs lock

Behavior:

Unmount FUSE filesystem.

Wipe sensitive memory.

Destroy runtime session.

Remove temporary mountpoints.



---

Add Files

Command:

vaultfs add secret.pdf

Behavior:

Read file.

Split into chunks.

Encrypt chunks independently.

Store encrypted blobs.

Update encrypted metadata database.

Never expose plaintext filenames on disk.



---

Retrieve Files

Command:

vaultfs export file_id ./output/

Behavior:

Requires unlocked vault.

Decrypt chunks.

Validate integrity.

Rebuild file.

Export securely.



---

List Files

Command:

vaultfs list

Behavior:

Requires unlocked vault.

Decrypt metadata.

Show:

filename

size

creation date

tags




---

Delete Files

Command:

vaultfs delete file_id

Behavior:

Remove encrypted chunks.

Remove metadata.

Secure overwrite where possible.



---

Cryptography Requirements

Key Derivation

Use:

Argon2id


Parameters:

Memory: 256MB
Iterations: 4
Parallelism: 4
Key Length: 32 bytes
Salt: 16+ bytes

Go package:

import "golang.org/x/crypto/argon2"


---

Encryption

Use one of:

Preferred

XChaCha20-Poly1305

or

Alternative

AES-256-GCM

Requirements:

Random nonce per encryption.

Never reuse nonces.

AEAD mandatory.

Integrity verification mandatory.


Go packages:

import "golang.org/x/crypto/chacha20poly1305"

or:

import "crypto/aes"
import "crypto/cipher"


---

Directory Layout

~/.vaultfs/
 ├── config.enc
 ├── metadata.enc
 ├── objects/
 │    ├── aa/
 │    ├── ab/
 │    └── ...
 ├── journal/
 ├── sessions/
 └── temp/


---

File Storage Model

Each file:

1. Split into chunks.


2. Chunk size:



4 MB

3. Each chunk:



plaintext chunk
   ↓
compress (optional)
   ↓
encrypt
   ↓
store as object


---

Object Naming

Object names should:

Never reveal original filename.

Use:


SHA-256(chunk ciphertext)

Example:

objects/ab/ab329df9328...


---

Metadata Database

Metadata must be encrypted.

Suggested structure:

{
  "id": "uuid",
  "filename": "secret.pdf",
  "size": 12345,
  "chunks": [
    "chunk1",
    "chunk2"
  ],
  "created": 123456789,
  "modified": 123456789
}

Entire metadata DB should be encrypted before writing.


---

Filename Encryption

Filenames must never appear plaintext on disk.

Use:

Separate filename encryption key.

Deterministic encryption optional.

Otherwise use metadata mapping.



---

Memory Security

Requirements:

Zero sensitive byte slices after use.

Avoid long-lived plaintext buffers.

Prevent accidental logging.

Disable core dumps if possible.

Lock memory pages if supported.


Linux syscalls:

unix.Mlock()
unix.Munlock()


---

FUSE Integration

Use:

bazil.org/fuse

or:

github.com/hanwen/go-fuse

Features:

Mount encrypted vault.

Transparent decryption.

Read/write support.

Lazy chunk loading.

Auto lock timeout.


Mount example:

~/vault_mount


---

CLI Design

Use:

github.com/spf13/cobra

Commands:

vaultfs init
vaultfs unlock
vaultfs lock
vaultfs add
vaultfs export
vaultfs delete
vaultfs list
vaultfs status
vaultfs mount
vaultfs unmount
vaultfs change-password


---

Config Structure

Example:

{
  "version": 1,
  "kdf": "argon2id",
  "cipher": "xchacha20poly1305",
  "created": 123456789
}

Encrypted before storage.


---

Session Handling

When unlocked:

Store temporary session token in memory.

Optional UNIX socket daemon.

Auto-expire after inactivity.

Support multi-process access.



---

Integrity Protection

Requirements:

Every encrypted object authenticated.

Metadata authenticated.

Config authenticated.

Reject tampered data.



---

Logging

Requirements:

Never log plaintext secrets.

Structured logs.

Debug mode optional.


Use:

log/slog


---

Concurrency

Requirements:

Parallel chunk encryption.

Worker pool.

Thread-safe metadata updates.


Use:

sync.RWMutex
sync.WaitGroup
context.Context


---

Testing

Include:

Unit tests.

Integration tests.

Encryption/decryption tests.

Corruption detection tests.

Wrong password tests.

FUSE mount tests.


Target:

80%+ coverage


---

Recommended Packages

cmd/
internal/
pkg/

Detailed layout:

vaultfs/
 ├── cmd/
 │    ├── root.go
 │    ├── init.go
 │    ├── unlock.go
 │    ├── add.go
 │    └── export.go
 │
 ├── internal/
 │    ├── crypto/
 │    ├── metadata/
 │    ├── objects/
 │    ├── session/
 │    ├── fuse/
 │    ├── config/
 │    ├── storage/
 │    └── memory/
 │
 ├── tests/
 ├── go.mod
 └── main.go


---

Crypto Implementation Rules

MANDATORY:

Never invent crypto.

Never use ECB.

Never use static IVs.

Never use SHA-1.

Never derive keys manually.

Never reuse nonces.

Never compare secrets with ==.


Use:

subtle.ConstantTimeCompare()


---

Password Change Flow

Command:

vaultfs change-password

Behavior:

Verify old password.

Generate new salt.

Re-encrypt master keys.

Preserve object data.



---

Auto Lock

Feature:

Lock after inactivity timeout.

Implementation:

Activity tracker.

Background goroutine.

Session expiration.



---

Optional Features

Deniable Vault

Support hidden secondary vault.

Decoy Mode

Mount fake filesystem.

Secure Delete

Multi-pass overwrite where filesystem supports.

Compression

Compress before encryption.

Remote Sync

Sync encrypted blobs to:

S3

WebDAV

SSH

rsync



---

Linux Security Hardening

Apply:

prctl(PR_SET_DUMPABLE, 0)

Optional:

seccomp

namespaces

private tmpfs

mount restrictions



---

File Chunk Structure

Example binary layout:

[magic]
[version]
[nonce]
[ciphertext]
[tag]


---

Metadata Encryption Flow

metadata JSON
   ↓
serialize
   ↓
encrypt AEAD
   ↓
write metadata.enc


---

Export Security

Requirements:

Prevent path traversal.

Sanitize filenames.

Require explicit output directory.



---

Error Handling

Requirements:

Typed errors.

Wrapped errors.

No secret leakage.


Use:

fmt.Errorf("decrypt failed: %w", err)


---

Build Requirements

Linux build:

CGO_ENABLED=0 go build -ldflags="-s -w"

Static build optional.


---

Example User Flow

vaultfs init
vaultfs unlock
vaultfs add secret.pdf
vaultfs list
vaultfs export file123 ./output
vaultfs lock


---

Implementation Quality Requirements

The generated code should:

Be real production-quality code.

Compile successfully.

Include proper package separation.

Avoid placeholder implementations.

Avoid pseudocode.

Include actual cryptographic operations.

Include actual filesystem operations.

Include actual chunk processing.

Include actual CLI wiring.

Include actual tests.

Include comments explaining security decisions.



---

Performance Requirements

Handle large files.

Stream encryption.

Avoid loading entire files into memory.

Use buffered I/O.

Support parallel chunk operations.



---

Threat Model

Protect against:

Offline disk theft.

Filesystem inspection.

Metadata leakage.

Unauthorized file recovery.

Tampering.

Wrong-password brute force.

Partial corruption.


Not required:

Kernel compromise.

Hardware implants.

Cold boot attacks.

RAM scraping by root.



---

Deliverables

Generate:

1. Complete Go source.


2. go.mod.


3. README.md.


4. Example config.


5. Unit tests.


6. Build instructions.


7. Threat model notes.


8. Security notes.


9. FUSE mounting logic.


10. Chunk storage implementation.


11. Metadata encryption implementation.


12. CLI implementation.


13. Password change implementation.


14. Session management.


15. Auto lock support.



The implementation must be detailed and extensive.