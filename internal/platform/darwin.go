//go:build darwin

package platform

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/bpicori/red-keep/internal/profile"
	"github.com/bpicori/red-keep/internal/proxy"
)

const SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec"

// darwinSensitivePaths are always denied in the sandbox.
var darwinSensitivePaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/etc/master.passwd",
	"/private/etc/shadow",
	"/private/etc/passwd",
	"/private/etc/sudoers",
	"/private/etc/master.passwd",
	"/var/db/dslocal",
	"/var/run/secrets",
	"/private/var/db/dslocal",
	"/private/var/run/secrets",
	"/System/Library",
	"/Library/Keychains",
	"/Network",
}

type darwinPlatform struct{}

// New returns the Platform implementation for macOS.
func New() (Platform, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	return &darwinPlatform{}, nil
}

func (d *darwinPlatform) SensitivePaths() []string {
	return darwinSensitivePaths
}

func (d *darwinPlatform) GenerateProfile(p *profile.Profile) (string, error) {
	b := newDarwinProfileBuilder(p)
	b.writeProfileHeader()
	b.writeProcessRules()
	b.writeSystemRules()
	b.writeSensitivePathDenyRules()
	b.writeUserPathRules()
	b.writeTemporaryDirectoryRule()
	b.writeWorkingDirectoryRule()
	b.writePTYRules()
	b.writeNetworkRules()
	return b.sb.String(), nil
}

func (d *darwinPlatform) Exec(p *profile.Profile, opts ExecOptions) (int, error) {
	// Start proxy only when domain filters are configured.
	var proxyAddr string
	if hasDomainFilters(p) {
		prx := proxy.New(p.AllowDomains, p.DenyDomains)
		prx.OnBlocked = func(domain string) {
			fmt.Fprintf(os.Stderr, "[red-keep] blocked connection to %q (domain not allowed by policy)\n", domain)
		}
		addr, err := prx.Start()
		if err != nil {
			return -1, fmt.Errorf("start filtering proxy: %w", err)
		}
		proxyAddr = addr
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			prx.Stop(ctx)
		}()
	}

	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		return -1, err
	}

	tmpFile, err := os.CreateTemp("", "red-keep-sandbox-*.sb")
	if err != nil {
		return -1, fmt.Errorf("create temp profile: %w", err)
	}
	profilePath := tmpFile.Name()
	defer os.Remove(profilePath)

	if _, err := tmpFile.WriteString(sbpl); err != nil {
		tmpFile.Close()
		return -1, fmt.Errorf("write profile: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return -1, fmt.Errorf("close profile: %w", err)
	}

	// Run: sandbox-exec -f <profile> -- <command> [args...]
	args := append([]string{"-f", profilePath, "--"}, p.Command...)
	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, SANDBOX_EXEC_PATH, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}
	if opts.Stdout != nil {
		cmd.Stdout = opts.Stdout
	}
	if opts.Stderr != nil {
		cmd.Stderr = opts.Stderr
	}

	if p.WorkDir != "" {
		cmd.Dir = p.WorkDir
	}

	// Route HTTP/HTTPS through local filtering proxy.
	if proxyAddr != "" {
		baseEnv := os.Environ()
		if len(opts.Env) > 0 {
			baseEnv = append([]string{}, opts.Env...)
		}
		cmd.Env = proxyEnvWithBase(baseEnv, proxyAddr)
	} else if len(opts.Env) > 0 {
		cmd.Env = append([]string{}, opts.Env...)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start sandbox-exec: %w", err)
	}

	childPID := cmd.Process.Pid

	// Forward SIGINT/SIGTERM to child process group.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case sig := <-sigCh:
				_ = syscall.Kill(-childPID, sig.(syscall.Signal))
			case <-done:
				signal.Stop(sigCh)
				return
			}
		}
	}()

	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()

	<-done

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
		}
		return -1, waitErr
	}
	return 0, nil
}

func (d *darwinPlatform) RunInternalSandboxExec(_ []string) (int, error) {
	return 0, nil
}

// proxyEnv returns environment with proxy vars set.
// Existing proxy vars are removed first, then replaced.
func proxyEnv(addr string) []string {
	return proxyEnvWithBase(os.Environ(), addr)
}

func proxyEnvWithBase(baseEnv []string, addr string) []string {
	proxyURL := "http://" + addr

	skip := map[string]bool{
		"HTTP_PROXY":  true,
		"http_proxy":  true,
		"HTTPS_PROXY": true,
		"https_proxy": true,
		"NO_PROXY":    true,
		"no_proxy":    true,
		"ALL_PROXY":   true,
		"all_proxy":   true,
	}

	env := make([]string, 0, len(baseEnv)+6)
	for _, e := range baseEnv {
		name, _, _ := strings.Cut(e, "=")
		if skip[name] {
			continue
		}
		env = append(env, e)
	}

	return append(env,
		"HTTP_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=",
		"no_proxy=",
	)
}

type darwinProfileBuilder struct {
	sb strings.Builder
	p  *profile.Profile
}

func newDarwinProfileBuilder(p *profile.Profile) *darwinProfileBuilder {
	return &darwinProfileBuilder{p: p}
}

// writeProfileHeader writes SBPL header and defaults.
func (b *darwinProfileBuilder) writeProfileHeader() {
	// SBPL version.
	b.sb.WriteString("(version 1)\n")
	// Log debug messages for every denied operation
	b.sb.WriteString("(debug deny)\n")
	// Deny everything by default; later rules allow specific actions.
	b.sb.WriteString("(deny default)\n\n")
}

func (b *darwinProfileBuilder) writeProcessRules() {
	// Allow the main command to start.
	// AllowExec only controls child process creation.
	b.sb.WriteString("; Process operations\n")
	b.sb.WriteString("(allow process-exec*)\n")
	if b.p.AllowExec {
		b.sb.WriteString("(allow process-fork)\n")
	} else {
		b.sb.WriteString("(deny process-fork)\n")
	}
	b.sb.WriteString("(allow process-info* (target self))\n")
	b.sb.WriteString("(deny process-info* (target others))\n\n")
}

func (b *darwinProfileBuilder) writeSystemRules() {
	// Minimal system operations needed to run.
	b.sb.WriteString("; System operations\n")
	b.sb.WriteString("(allow sysctl-read)\n")
	b.sb.WriteString("(allow mach-lookup)\n")
	b.sb.WriteString("(allow ipc-posix-shm)\n")
	b.sb.WriteString("(allow signal (target self))\n")
	b.sb.WriteString("(allow system-socket)\n")
	b.sb.WriteString("(allow system-fsctl)\n")
	b.sb.WriteString("(allow system-info)\n\n")

	// Read standard system paths needed for binary lookup and dyld.
	b.sb.WriteString("; System paths for binary resolution and dyld\n")
	// Deny known-sensitive paths before broad root/system read allowances.
	writePathRules(&b.sb, "deny file-read* file-write*", darwinSensitivePaths)
	writeLiteralRule(&b.sb, "allow file-read*", "/")
	writePathRules(&b.sb, "allow file-read*", []string{
		"/usr/lib",
		"/usr/bin",
		"/bin",
		"/usr/sbin",
		"/sbin",
		"/usr/share",
		"/private/var/db/dyld",
	})
	writeLiteralRule(&b.sb, "allow file-read* file-write*", "/dev/null")
	writeLiteralRule(&b.sb, "allow file-read*", "/dev/urandom")
	writeLiteralRule(&b.sb, "allow file-read*", "/dev/dtracehelper")
	writeSubpathRule(&b.sb, "allow file-map-executable", "/")
	b.sb.WriteString("\n")

	// Allow symlink traversal paths used on macOS.
	// /var, /tmp, /etc resolve to /private/... at runtime.
	b.sb.WriteString("; macOS symlink traversal\n")
	for _, path := range []string{"/var", "/tmp", "/etc", "/private", "/private/var", "/private/tmp", "/private/etc"} {
		writeLiteralRule(&b.sb, "allow file-read*", path)
	}
	b.sb.WriteString("\n")
}

func (b *darwinProfileBuilder) writeSensitivePathDenyRules() {
	// Always deny sensitive paths.
	// Deny read/write ops including rename and unlink.
	b.sb.WriteString("; Deny sensitive paths\n")
	writePathRules(&b.sb, "deny file-read* file-write*", darwinSensitivePaths)

	// Deny rename/unlink on parent dirs to prevent bypass via directory moves.
	b.sb.WriteString("; Deny rename/unlink on ancestors of sensitive paths (bypass prevention)\n")
	ancestorSet := make(map[string]struct{})
	for _, sp := range darwinSensitivePaths {
		for _, anc := range pathAncestors(sp) {
			ancestorSet[anc] = struct{}{}
		}
	}
	ancestors := make([]string, 0, len(ancestorSet))
	for anc := range ancestorSet {
		ancestors = append(ancestors, anc)
	}
	sort.Strings(ancestors)
	writePathRules(&b.sb, "deny file-write*", ancestors)
	b.sb.WriteString("\n")
}

func (b *darwinProfileBuilder) writeUserPathRules() {
	// User read paths.
	b.sb.WriteString("; Read paths\n")
	writePathRules(&b.sb, "allow file-read*", b.p.ReadPaths)

	// User write paths.
	b.sb.WriteString("; Write paths\n")
	writePathRules(&b.sb, "allow file-write*", b.p.WritePaths)

	// User read-write paths.
	b.sb.WriteString("; Read-write paths\n")
	writePathRules(&b.sb, "allow file-read* file-write*", b.p.RWPaths)
}

func (b *darwinProfileBuilder) writeTemporaryDirectoryRule() {
	// Allow TMPDIR for temp files.
	// Resolve symlinks because sandbox rules use resolved paths.
	b.sb.WriteString("; Temporary directory\n")
	tmpDir := os.TempDir()
	if tmpDir == "" {
		return
	}
	if resolved, err := filepath.EvalSymlinks(tmpDir); err == nil {
		tmpDir = resolved
	}
	writeSubpathRule(&b.sb, "allow file-read* file-write*", tmpDir)
}

func (b *darwinProfileBuilder) writeWorkingDirectoryRule() {
	// Allow working directory.
	if b.p.WorkDir == "" {
		return
	}
	b.sb.WriteString("; Working directory\n")
	writeSubpathRule(&b.sb, "allow file-read* file-write*", b.p.WorkDir)
}

func (b *darwinProfileBuilder) writePTYRules() {
	// Optional PTY access.
	if !b.p.AllowPTY {
		return
	}
	b.sb.WriteString("; Pseudo-terminal access\n")
	writeSubpathRule(&b.sb, "allow file-read* file-write*", "/dev")
}

func (b *darwinProfileBuilder) writeNetworkRules() {
	// Network rules.
	b.sb.WriteString("; Network\n")
	if b.p.AllowNet {
		b.sb.WriteString("(allow network-outbound)\n")
		b.sb.WriteString("(allow network-inbound)\n")
		b.sb.WriteString("(allow network-bind)\n")
		// Allow TLS certs and resolver config reads.
		writeSubpathRule(&b.sb, "allow file-read*", "/private/etc/ssl")
		writeLiteralRule(&b.sb, "allow file-read*", "/private/etc/resolv.conf")
		return
	}
	if hasDomainFilters(b.p) {
		// Domain filtering is done by a local proxy.
		// Sandbox only allows outbound traffic to localhost.
		b.sb.WriteString("; Domain filtering via local proxy (HTTP_PROXY/HTTPS_PROXY)\n")
		b.sb.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
		// Allow TLS cert and resolver config reads for HTTPS.
		writeSubpathRule(&b.sb, "allow file-read*", "/private/etc/ssl")
		writeLiteralRule(&b.sb, "allow file-read*", "/private/etc/resolv.conf")
		return
	}
	// Else, deny all network access.
	b.sb.WriteString("(deny network*)\n")
}

func hasDomainFilters(p *profile.Profile) bool {
	return len(p.AllowDomains) > 0 || len(p.DenyDomains) > 0
}

func writeSubpathRule(sb *strings.Builder, action, path string) {
	sb.WriteString(fmt.Sprintf("(%s (subpath \"%s\"))\n", action, escapeSBPLPath(path)))
}

func writePathRules(sb *strings.Builder, action string, paths []string) {
	for _, path := range paths {
		writeSubpathRule(sb, action, path)
	}
}

func writeLiteralRule(sb *strings.Builder, action, path string) {
	sb.WriteString(fmt.Sprintf("(%s (literal \"%s\"))\n", action, escapeSBPLPath(path)))
}

// escapeSBPLPath escapes backslashes and double quotes for use in SBPL strings.
func escapeSBPLPath(p string) string {
	p = strings.ReplaceAll(p, `\`, `\\`)
	p = strings.ReplaceAll(p, `"`, `\"`)
	return p
}

// pathAncestors returns ancestor directories of p, excluding root.
// Example: /private/etc/shadow -> [/private /private/etc]
func pathAncestors(p string) []string {
	p = filepath.Clean(p)
	if p == "" || p == "/" || p == "." {
		return nil
	}
	var ancestors []string
	for {
		dir := filepath.Dir(p)
		if dir == p || dir == "/" {
			break
		}
		ancestors = append(ancestors, dir)
		p = dir
	}
	return ancestors
}
