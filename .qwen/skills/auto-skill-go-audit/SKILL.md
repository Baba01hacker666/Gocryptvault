---
name: go-audit
description: Systematic Go codebase audit covering build, test, functional bugs, security, and missing features
source: auto-skill
extracted_at: '2026-06-16T08:12:24.121Z'
---

# Go Codebase Audit Workflow

Use this when asked to "find bugs", "audit the code", "review the codebase", or "find what's missing" in a Go project.

## Phase 1: Build & Test (always first)

Run these before deep reading — they surface the most objective issues immediately:

```sh
go build ./...          # compile errors
go test ./...           # test failures / build failures in test files
go vet ./...            # static analysis (optional but valuable)
```

- **Compile errors in test files count as test failures** — report them under build/test breakage.
- If the project uses build tags, test under each supported OS (e.g. `GOOS=linux`, `GOOS=darwin`).

## Phase 2: Structure Discovery

1. Read `README.md` for intended features, architecture, and CLI surface.
2. `ls -R` or directory listing with depth to understand package layout.
3. Map the dependency graph by following imports from `main.go` downward.

## Phase 3: Systematic File Reading

Read every `.go` file, one package at a time, following the import hierarchy:

- **Commands first** (`cmd/`) — understand the user-facing surface
- **Core logic** (`internal/`) — the business rules
- **Public API** (`pkg/`) — exported interfaces
- **Tests** (`tests/`, `*_test.go`) — reveals edge cases and untested paths

For each file, track:
- What it claims to do (comments, function names)
- What it actually does (the implementation)
- Cross-references to other packages (imports, function calls)

## Phase 4: Cross-Reference Claims Against Reality

This is the highest-yield step. Specifically check:

1. **Comments that claim a fix** (e.g. `// FIXED HIGH-06: encrypts shards.json`). Verify the code actually does what the comment says. "Fixed" comments that lie are the most dangerous bugs — they give a false sense of security.

2. **Function signatures at call sites vs. definitions** — `grep` for each function name, verify arg counts match. Signature changes (adding/removing params) are a common source of broken call sites.

3. **Removed methods still referenced** — grep for removed RPC methods, deleted functions, renamed types.

4. **Default values that break the happy path** — if a feature is advertised but gated behind a flag that defaults to off, it may be effectively dead.

## Phase 5: Categorize

Group findings by severity:

| Category | Examples |
|----------|----------|
| **Build/Test Breakage** | Compile errors, test failures |
| **Functional Bugs** | Incorrect behavior, missing os.Rename, dead code paths |
| **Security Issues** | Plaintext storage, missing rate limiting, predictable IDs, RBAC bypass |
| **Missing/Incomplete** | Advertised features not implemented, stubs, half-finished work |
| **Code Quality** | Duplicated code, implicit coupling between files, resource leaks |

## Phase 6: Verify Before Reporting

- If a finding relies on a function not existing, **grep for it**.
- If a finding claims broken behavior, **read the actual code** — don't trust memory.
- For compile/test failures, **run the actual commands** — don't just guess.
