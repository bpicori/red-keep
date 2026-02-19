# Red Keep

A deny-by-default sandbox for AI agents. Lock down filesystem, network, and process access so autonomous tools can only touch what you explicitly allow.

**Supported platforms:** macOS (Seatbelt), Linux (Landlock + seccomp)

## Quick start

```bash
# Build
make build

# Run a command with read access to a project directory
red-keep run --allow-read /home/dev/project -- ls -la

# Read-only access to a project, no network
red-keep run --allow-read /home/dev/myproject -- grep -r "TODO" .

# Run with read-write access and full network
red-keep run --allow-rw /tmp/output --allow-net -- curl https://example.com -o /tmp/output/file

# Read-write to an output dir, network to specific APIs only
red-keep run \
  --allow-read /home/dev/project \
  --allow-rw /home/dev/project/output \
  --allow-domain api.openai.com \
  --allow-domain '*.githubusercontent.com' \
  -- python agent.py

# Full network access, block known-bad domains
red-keep run \
  --allow-rw /tmp/workspace \
  --deny-domain evil.com \
  --deny-domain '*.malware.net' \
  -- node bot.js

# Interactive session with PTY
red-keep run --allow-rw /home/dev/project --allow-pty -- bash

# Run in a specific working directory
red-keep run --dir /home/dev/project --allow-read /home/dev/project -- pwd

# Inspect the generated profile
red-keep run --show-profile --allow-read /home/dev/project --allow-net -- echo test

# Run using a YAML options file
red-keep run --profile ./profile.yaml -- echo hello

```

## Flags

#### Filesystem access

| Flag                   | Repeatable | Description                                             |
| ---------------------- | ---------- | ------------------------------------------------------- |
| `--allow-read <path>`  | Yes        | Grant **read-only** access to a path (and its subtree)  |
| `--allow-write <path>` | Yes        | Grant **write-only** access to a path (and its subtree) |
| `--allow-rw <path>`    | Yes        | Grant **read-write** access to a path (and its subtree) |

All paths must be absolute. Paths are resolved to their canonical form (symlinks resolved, cleaned). Access to [sensitive paths](#sensitive-paths) is always denied regardless of flags.

#### Network access

| Flag                      | Repeatable | Description                                                                                            |
| ------------------------- | ---------- | ------------------------------------------------------------------------------------------------------ |
| `--allow-net`             | No         | Allow **all** network access. Cannot be combined with `--allow-domain` or `--deny-domain`.            |
| `--allow-domain <domain>` | Yes        | Allow network access to a specific domain (enables filtered mode). Supports wildcards: `*.example.com` |
| `--deny-domain <domain>`  | Yes        | Deny network access to a specific domain (enables filtered mode). Supports wildcards: `*.example.com`  |

**Network modes:**

- **Deny (default):** All outbound/inbound network access is blocked. Local Unix sockets are allowed for IPC.
- **Allow:** Unrestricted network access (`--allow-net`). Cannot be combined with domain filters.
- **Filtered:** Domain-level control via a local forward proxy. Use `--allow-domain` (allowlist) or `--deny-domain` (denylist) without `--allow-net`. `--allow-domain` and `--deny-domain` are mutually exclusive and cannot be combined.

#### Process and PTY

| Flag           | Description                                                                                                                                              |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--allow-exec` | Allow the sandboxed process to spawn child processes via exec. Without this, only system binaries in `/bin`, `/usr/bin`, `/usr/local/bin` are permitted. |
| `--allow-pty`  | Allow pseudo-terminal allocation (needed for interactive commands)                                                                                       |

#### Execution options

| Flag               | Description                                                      |
| ------------------ | ---------------------------------------------------------------- |
| `--dir <path>`     | Set the working directory for the sandboxed command              |
| `--show-profile`   | Print the generated sandbox profile to stdout and exit (dry run) |
| `--profile <path>` | Load `run` options from a YAML file                              |

#### Profile file format

`--profile` accepts a YAML document with the same keys as the CLI options.

```yaml
read_paths:
  - /home/dev/project
allow_domains:
  - api.openai.com
allow_exec: true
work_dir: /home/dev/project
command:
  - python
  - agent.py
```

- CLI flags can still be passed and override booleans/strings/command from file.
- Path/domain list flags are additive with file values.

## Security model

### Deny by default

Everything is denied unless explicitly allowed. The sandbox starts with zero permissions and adds only what you specify.

### Filesystem

- **System paths** are automatically granted read access (OS libraries, binaries, shared caches, timezone data, `/tmp`).
- **Temp directories** (`/tmp`, `/var/tmp`, platform equivalents) are automatically granted write access.
- **User paths** require explicit `--allow-read`, `--allow-write`, or `--allow-rw` flags.
- **Sensitive paths** are **always denied** regardless of any flags (see below).

### Sensitive paths

Sensitive locations under `$HOME` are always blocked (read and write), including common credential stores and secret files such as:

- SSH and cloud credentials (for example `~/.ssh`, `~/.aws`, `~/.config/gcloud`)
- CLI and package manager auth material (for example `~/.config/gh`, `~/.docker`, `~/.npmrc`)
- OS and password-manager key stores (for example `~/Library/Keychains`, 1Password, Bitwarden)
- Secret-bearing config files (for example `~/.env`, `~/.netrc`, `~/.git-credentials`)

### Network filtering (filtered mode)

When using `--allow-domain` / `--deny-domain`, a local HTTP/HTTPS forward proxy enforces domain-level access control:

- The sandbox blocks all direct outbound connections except to `localhost`
- The proxy intercepts HTTP and HTTPS CONNECT requests
- Domain names are checked against the allow/deny lists before forwarding
- Wildcard patterns like `*.example.com` match any subdomain
- `HTTP_PROXY` / `HTTPS_PROXY` environment variables are set automatically

## Platform implementation

### macOS

Uses Apple's Seatbelt (SBPL profiles) via `sandbox-exec`. Seatbelt is a kernel-level mandatory access control framework that enforces file, network, process, and IPC restrictions. The generated profile:

- Denies everything by default
- Adds read access for system paths (OS libraries, binaries, shared caches, timezone data)
- Adds write access for temp directories
- Controls network access via Seatbelt rules or the filtering proxy
- Restricts `process-exec` to system binaries unless `--allow-exec` is set

### Linux

Uses a combination of:

- **Landlock** — Filesystem access control (kernel 5.13+)
- **seccomp-bpf** — System call filtering
- **Local filtering proxy** — Domain-level network filtering (`--allow-domain`, `--deny-domain`)

Linux runs in fail-closed mode: if required kernel capabilities for Landlock/seccomp are unavailable, sandbox execution fails with a clear error.

## Development

```bash
make build              # Compile to bin/red-keep
make test               # Run unit tests
make integration-test   # Run integration tests (macOS, builds first)
make vet                # Run go vet
make fmt                # Format source
make clean              # Remove build artifacts
```

## License

MIT
