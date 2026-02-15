# red-keep

A deny-by-default sandbox for AI agents. Restricts filesystem, network, and process access so autonomous tools can only touch what you explicitly allow.

**Supported platforms:** macOS (Seatbelt), Linux (Landlock + seccomp) *(Linux support in progress)*

## Quick start

```bash
# Build
make build

# Run a command with read access to a project directory
red-keep run --allow-read /home/dev/project -- ls -la

# Run with read-write access and full network
red-keep run --allow-rw /tmp/output --allow-net -- curl https://example.com -o /tmp/output/file

# Preview the generated sandbox profile without executing
red-keep run --show-profile --allow-read /home/dev/project -- echo test
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
- **Filtered:** Domain-level control via a local forward proxy. When `--allow-domain` is used, only listed domains are reachable (allowlist). When `--deny-domain` is used, all domains are reachable except listed ones (denylist). If both are set, allowlist takes precedence.

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
| `--monitor`       | Stream sandbox violation events to stderr in real time             |

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

# Monitor violations while running
red-keep run --allow-read /home/dev/project --monitor -- python risky_script.py

# Inspect the generated profile
red-keep run --show-profile --allow-read /home/dev/project --allow-net -- echo test
```

## Platform implementation

### macOS

Uses Apple's Seatbelt (SBPL profiles) via `sandbox-exec` or the `sandbox_init()` C API. Seatbelt is a kernel-level mandatory access control framework.

### Linux *(planned)*

Will use a combination of:
- **Landlock** - Filesystem access control (kernel 5.13+)
- **seccomp-bpf** - System call filtering
- **Network namespaces / iptables** - Network access control

## Development

```bash
make build     # Compile to bin/red-keep
make test      # Run all tests
make vet       # Run go vet
make fmt       # Format source
make clean     # Remove build artifacts
```

## License

MIT
