# red-keep

![Red Keep project banner](red-keep-image.png)

A deny-by-default sandbox for AI agents. Lock down filesystem, network, and process access so autonomous tools can only touch what you explicitly allow.

**Supported platforms:** macOS (Seatbelt), Linux (Landlock + seccomp)

## Quick start

```bash
# Build
make build

# Run a command with read access to a project directory
red-keep run --allow-read /home/dev/project -- ls -la

# Run with read-write access and full network
red-keep run --allow-rw /tmp/output --allow-net -- curl https://example.com -o /tmp/output/file

# Run with read-write access and full network and allow-domain example.com
red-keep run --allow-rw /tmp/output --allow-net --allow-domain example.com -- curl https://example.com -o /tmp/output/file

# Run with read-write access and full network and deny-domain example.com
red-keep run --allow-rw /tmp/output --allow-net --deny-domain example.com -- curl https://example.com -o /tmp/output/file

```

## Commands

| Command   | Description                            |
|-----------|----------------------------------------|
| `run`     | Run a command inside the sandbox       |
| `version` | Print version information              |
| `help`    | Show help message                      |

## Flags

### Global flags

| Flag              | Short | Description                |
|-------------------|-------|----------------------------|
| `--help`          | `-h`  | Show help message          |
| `--version`       | `-v`  | Print version information  |

### `run` command flags

#### Filesystem access

| Flag                    | Repeatable | Description                                                             |
|-------------------------|------------|-------------------------------------------------------------------------|
| `--allow-read <path>`   | Yes        | Grant **read-only** access to a path (and its subtree)                  |
| `--allow-write <path>`  | Yes        | Grant **write-only** access to a path (and its subtree)                 |
| `--allow-rw <path>`     | Yes        | Grant **read-write** access to a path (and its subtree)                 |

All paths must be absolute. Paths are resolved to their canonical form (symlinks resolved, cleaned). Access to [sensitive paths](#sensitive-paths) is always denied regardless of flags.

#### Network access

| Flag                      | Repeatable | Description                                                                                             |
|---------------------------|------------|---------------------------------------------------------------------------------------------------------|
| `--allow-net`             | No         | Allow **all** network access (overrides domain filters)                                                 |
| `--allow-domain <domain>` | Yes        | Allow network access to a specific domain (enables filtered mode). Supports wildcards: `*.example.com`  |
| `--deny-domain <domain>`  | Yes        | Deny network access to a specific domain (enables filtered mode). Supports wildcards: `*.example.com`   |

**Network modes:**

- **Deny (default):** All outbound/inbound network access is blocked. Local Unix sockets are allowed for IPC.
- **Allow:** Unrestricted network access (`--allow-net`).
- **Filtered:** Domain-level control via a local forward proxy. When `--allow-domain` is used, only listed domains are reachable (allowlist). When `--deny-domain` is used, all domains are reachable except listed ones (denylist). The two flags are mutually exclusive and cannot be combined.

#### Process and PTY

| Flag            | Description                                                                                     |
|-----------------|-------------------------------------------------------------------------------------------------|
| `--allow-exec`  | Allow the sandboxed process to spawn child processes via exec. Without this, only system binaries in `/bin`, `/usr/bin`, `/usr/local/bin` are permitted. |
| `--allow-pty`   | Allow pseudo-terminal allocation (needed for interactive commands)                               |

#### Execution options

| Flag              | Description                                                        |
|-------------------|--------------------------------------------------------------------|
| `--dir <path>`    | Set the working directory for the sandboxed command                 |
| `--show-profile`  | Print the generated sandbox profile to stdout and exit (dry run)   |

## Security model

### Deny by default

Everything is denied unless explicitly allowed. The sandbox starts with zero permissions and adds only what you specify.

### Filesystem

- **System paths** are automatically granted read access (OS libraries, binaries, shared caches, timezone data, `/tmp`).
- **Temp directories** (`/tmp`, `/var/tmp`, platform equivalents) are automatically granted write access.
- **User paths** require explicit `--allow-read`, `--allow-write`, or `--allow-rw` flags.
- **Sensitive paths** are **always denied** regardless of any flags (see below).

### Sensitive paths

The following paths relative to `$HOME` are always blocked (read and write), protecting credentials, keys, and tokens from exfiltration:

| Path                                        | Purpose                    |
|---------------------------------------------|----------------------------|
| `~/.ssh`                                    | SSH keys                   |
| `~/.aws`                                    | AWS credentials            |
| `~/.azure`                                  | Azure credentials          |
| `~/.gnupg`, `~/.gpg`                        | GPG keys                   |
| `~/.config/gcloud`                          | Google Cloud credentials   |
| `~/.config/gh`                              | GitHub CLI tokens          |
| `~/.docker`                                 | Docker credentials         |
| `~/.kube`                                   | Kubernetes config          |
| `~/.npm/_auth`                              | npm auth tokens            |
| `~/.netrc`                                  | Network credentials        |
| `~/.git-credentials`                        | Git credential store       |
| `~/Library/Keychains` *(macOS)*             | macOS Keychain             |
| `~/Library/Application Support/1Password`   | 1Password data             |
| `~/Library/Application Support/Bitwarden`   | Bitwarden data             |
| `~/.env`                                    | Environment secrets        |
| `~/.npmrc`                                  | npm config (may have tokens)|
| `~/.pypirc`                                 | PyPI credentials           |
| `~/.gem/credentials`                        | RubyGems credentials       |

### Bypass prevention

The sandbox blocks rename/move (`rename(2)`, `unlink(2)`) operations on sensitive paths and their ancestor directories. This prevents directory-swap attacks where an attacker could:

1. Move a denied directory to a readable location (read bypass)
2. Rename a parent directory, modify contents, then rename back (write bypass)

### Network filtering (filtered mode)

When using `--allow-domain` / `--deny-domain`, a local HTTP/HTTPS forward proxy enforces domain-level access control:

- The sandbox blocks all direct outbound connections except to `localhost`
- The proxy intercepts HTTP and HTTPS CONNECT requests
- Domain names are checked against the allow/deny lists before forwarding
- Wildcard patterns like `*.example.com` match any subdomain
- `HTTP_PROXY` / `HTTPS_PROXY` environment variables are set automatically

## Examples

```bash
# Read-only access to a project, no network
red-keep run --allow-read /home/dev/myproject -- grep -r "TODO" .

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

# Inspect the generated profile
red-keep run --show-profile --allow-read /home/dev/project --allow-net -- echo test
```

## Architecture

```
cmd/red-keep/          CLI entry point
internal/
  cli/                 Flag parsing & command orchestration
  profile/             Platform-agnostic sandbox profile & validation
  platform/            OS-specific implementations (darwin, linux)
  proxy/               HTTP/HTTPS forward proxy for domain filtering
tests/                 Integration tests (macOS)
```

The sandbox flow:

1. **Parse & validate** — CLI flags are parsed into a `Profile` struct. Paths are resolved (symlinks evaluated), checked against sensitive-path lists, and validated for correctness.
2. **Generate profile** — The platform layer translates the `Profile` into an OS-native policy (e.g. SBPL on macOS).
3. **Proxy (filtered mode)** — When domain rules are active, a local HTTP/HTTPS forward proxy starts on a random localhost port. `HTTP_PROXY` / `HTTPS_PROXY` env vars are injected so the child process routes traffic through it.
4. **Execute** — The command runs inside the sandbox with the generated policy.

## Platform implementation

### macOS

Uses Apple's Seatbelt (SBPL profiles) via `sandbox-exec`. Seatbelt is a kernel-level mandatory access control framework that enforces file, network, process, and IPC restrictions. The generated profile:

- Denies everything by default
- Adds read access for system paths (OS libraries, binaries, shared caches, timezone data)
- Adds write access for temp directories
- Blocks `rename(2)` and `unlink(2)` on sensitive paths and their ancestors (bypass prevention)
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
