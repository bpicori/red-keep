//go:build darwin

package platform

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bpicori/red-keep/internal/profile"
	"github.com/bpicori/red-keep/internal/proxy"
)

// darwinSensitivePaths lists paths that must never be granted sandbox access
// on macOS. Any user-provided path that overlaps with these is rejected.
// Uses /private/... for paths under /etc and /var because macOS resolves those
// symlinks before sandbox checks.
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

func (d *darwinPlatform) GenerateProfile(p *profile.Profile) (string, error) {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(debug deny)\n")
	sb.WriteString("(deny default)\n\n")

	// Process operations.
	// process-exec* is always allowed because sandbox-exec applies the profile
	// before exec-ing the target command; denying it would prevent the initial
	// command from starting. AllowExec controls process-fork, which gates
	// whether the sandboxed process can spawn child processes.
	sb.WriteString("; Process operations\n")
	sb.WriteString("(allow process-exec*)\n")
	if p.AllowExec {
		sb.WriteString("(allow process-fork)\n")
	} else {
		sb.WriteString("(deny process-fork)\n")
	}
	sb.WriteString("(allow process-info* (target self))\n")
	sb.WriteString("(deny process-info* (target others))\n\n")

	// System operations required for basic execution
	sb.WriteString("; System operations\n")
	sb.WriteString("(allow sysctl-read)\n")
	sb.WriteString("(allow mach-lookup)\n")
	sb.WriteString("(allow ipc-posix-shm)\n")
	sb.WriteString("(allow signal (target self))\n")
	sb.WriteString("(allow system-socket)\n")
	sb.WriteString("(allow system-fsctl)\n")
	sb.WriteString("(allow system-info)\n\n")

	// Standard system directories required for binary resolution and loading.
	// execvp needs to read PATH directories, dyld needs libraries and cache.
	sb.WriteString("; System paths for binary resolution and dyld\n")
	sb.WriteString("(allow file-read* (literal \"/\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/usr/lib\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/usr/bin\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/bin\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/usr/sbin\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/sbin\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/usr/share\"))\n")
	sb.WriteString("(allow file-read* (subpath \"/private/var/db/dyld\"))\n")
	sb.WriteString("(allow file-read* file-write* (literal \"/dev/null\"))\n")
	sb.WriteString("(allow file-read* (literal \"/dev/urandom\"))\n")
	sb.WriteString("(allow file-read* (literal \"/dev/dtracehelper\"))\n")
	sb.WriteString("(allow file-map-executable (subpath \"/\"))\n\n")

	// macOS firmlink/symlink traversal. /var, /tmp, /etc are symlinks to
	// /private/var, /private/tmp, /private/etc. The sandbox checks paths
	// AFTER kernel symlink resolution, so SBPL rules must use the resolved
	// /private/... paths. These literal rules allow the kernel to follow
	// the symlinks during path traversal without granting access to contents.
	sb.WriteString("; macOS symlink traversal\n")
	sb.WriteString("(allow file-read* (literal \"/var\"))\n")
	sb.WriteString("(allow file-read* (literal \"/tmp\"))\n")
	sb.WriteString("(allow file-read* (literal \"/etc\"))\n")
	sb.WriteString("(allow file-read* (literal \"/private\"))\n")
	sb.WriteString("(allow file-read* (literal \"/private/var\"))\n")
	sb.WriteString("(allow file-read* (literal \"/private/tmp\"))\n")
	sb.WriteString("(allow file-read* (literal \"/private/etc\"))\n\n")

	// Always deny sensitive paths (defense in depth).
	// Deny file-read* and file-write* to block read, write, rename(2), and unlink(2).
	sb.WriteString("; Deny sensitive paths\n")
	for _, sp := range darwinSensitivePaths {
		escaped := escapeSBPLPath(sp)
		sb.WriteString(fmt.Sprintf("(deny file-read* file-write* (subpath \"%s\"))\n", escaped))
	}

	// Deny file-write* (rename, unlink) on ancestor directories to prevent
	// directory-swap attacks: move denied dir to readable location, or rename
	// parent, modify, rename back.
	sb.WriteString("; Deny rename/unlink on ancestors of sensitive paths (bypass prevention)\n")
	ancestorSet := make(map[string]bool)
	for _, sp := range darwinSensitivePaths {
		for _, anc := range pathAncestors(sp) {
			ancestorSet[anc] = true
		}
	}
	for anc := range ancestorSet {
		escaped := escapeSBPLPath(anc)
		sb.WriteString(fmt.Sprintf("(deny file-write* (subpath \"%s\"))\n", escaped))
	}
	sb.WriteString("\n")

	// User-granted read paths
	sb.WriteString("; Read paths\n")
	for _, path := range p.ReadPaths {
		escaped := escapeSBPLPath(path)
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath \"%s\"))\n", escaped))
	}

	// User-granted write paths
	sb.WriteString("; Write paths\n")
	for _, path := range p.WritePaths {
		escaped := escapeSBPLPath(path)
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", escaped))
	}

	// User-granted read-write paths
	sb.WriteString("; Read-write paths\n")
	for _, path := range p.RWPaths {
		escaped := escapeSBPLPath(path)
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write* (subpath \"%s\"))\n", escaped))
	}

	// TMPDIR for temporary files. Resolve symlinks because macOS sandbox
	// evaluates rules against resolved paths (e.g. /var -> /private/var).
	sb.WriteString("; Temporary directory\n")
	tmpDir := os.TempDir()
	if tmpDir != "" {
		if resolved, err := filepath.EvalSymlinks(tmpDir); err == nil {
			tmpDir = resolved
		}
		escaped := escapeSBPLPath(tmpDir)
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write* (subpath \"%s\"))\n", escaped))
	}

	// Working directory
	if p.WorkDir != "" {
		sb.WriteString("; Working directory\n")
		escaped := escapeSBPLPath(p.WorkDir)
		sb.WriteString(fmt.Sprintf("(allow file-read* file-write* (subpath \"%s\"))\n", escaped))
	}

	// PTY access
	if p.AllowPTY {
		sb.WriteString("; Pseudo-terminal access\n")
		sb.WriteString("(allow file-read* file-write* (subpath \"/dev\"))\n")
	}

	// Network
	sb.WriteString("; Network\n")
	if p.AllowNet {
		sb.WriteString("(allow network-outbound)\n")
		sb.WriteString("(allow network-inbound)\n")
		sb.WriteString("(allow network-bind)\n")
		// TLS and DNS require reading system certificates and resolver config.
		sb.WriteString("(allow file-read* (subpath \"/private/etc/ssl\"))\n")
		sb.WriteString("(allow file-read* (literal \"/private/etc/resolv.conf\"))\n")
	} else if len(p.AllowDomains) > 0 || len(p.DenyDomains) > 0 {
		// Domain-based filtering is enforced via a local HTTP proxy.
		// The sandbox restricts outbound to localhost where the proxy
		// listens; the proxy (running outside the sandbox) resolves DNS
		// and forwards only permitted domains.
		sb.WriteString("; Domain filtering via local proxy (HTTP_PROXY/HTTPS_PROXY)\n")
		sb.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
		// TLS certificates needed for end-to-end HTTPS through CONNECT tunnels.
		sb.WriteString("(allow file-read* (subpath \"/private/etc/ssl\"))\n")
		sb.WriteString("(allow file-read* (literal \"/private/etc/resolv.conf\"))\n")
	} else {
		sb.WriteString("(deny network*)\n")
	}

	return sb.String(), nil
}

func (d *darwinPlatform) Exec(p *profile.Profile, onViolation ViolationHandler) (int, error) {
	// Start the domain-filtering proxy when allow/deny domains are configured.
	var proxyAddr string
	if len(p.AllowDomains) > 0 || len(p.DenyDomains) > 0 {
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

	// Build sandbox-exec command: sandbox-exec -f <profile> -- <command> [args...]
	args := append([]string{"-f", profilePath, "--"}, p.Command...)
	cmd := exec.Command("sandbox-exec", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if p.WorkDir != "" {
		cmd.Dir = p.WorkDir
	}

	// Route the sandboxed process's HTTP/HTTPS traffic through our filtering
	// proxy so domain-based rules are enforced. We clear any pre-existing
	// proxy env vars to prevent the child from bypassing the filter.
	if proxyAddr != "" {
		cmd.Env = proxyEnv(proxyAddr)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start sandbox-exec: %w", err)
	}

	childPID := cmd.Process.Pid
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if onViolation != nil {
		wg.Add(1)
		cmdName := ""
		if len(p.Command) > 0 {
			cmdName = p.Command[0]
		}
		go func() {
			defer wg.Done()
			d.monitorViolations(ctx, childPID, cmdName, onViolation)
		}()
	}

	// Forward SIGINT, SIGTERM to child process group
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
	cancel()
	if onViolation != nil {
		wg.Wait()
	}

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

// proxyEnv returns a copy of the current environment with proxy variables
// set to route traffic through the filtering proxy at addr. Existing proxy
// env vars are stripped to prevent the child process from bypassing the filter.
func proxyEnv(addr string) []string {
	proxyURL := "http://" + addr

	// Proxy-related env var names to replace (both cases for portability).
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

	environ := os.Environ()
	env := make([]string, 0, len(environ)+6)
	for _, e := range environ {
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

// violationLineRegex matches sandboxd log lines like:
// "sandboxd(xxx): process(pid) deny file-read-data /path/to/file"
// or "Violation: deny(1) file-read-data /path"
var violationLineRegex = regexp.MustCompile(`(?i)(?:sandboxd|violation).*?(?:deny|violation).*?(\S+)\s+([^\s]+)(?:\s+(.+))?`)

func (d *darwinPlatform) monitorViolations(ctx context.Context, pid int, cmdName string, onViolation ViolationHandler) {
	// Use log stream to capture sandbox violations. Sandbox violations are reported
	// by sandboxd with subsystem com.apple.sandbox.reporting. Filter by cmdName
	// when possible to reduce noise from other processes.
	args := []string{
		"stream",
		"--predicate", `subsystem == "com.apple.sandbox.reporting"`,
		"--style", "syslog",
	}
	cmd := exec.CommandContext(ctx, "log", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	defer cmd.Wait()

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		line := scanner.Text()
		if cmdName != "" && !strings.Contains(line, cmdName) {
			continue
		}
		if !strings.Contains(strings.ToLower(line), "deny") && !strings.Contains(line, "violation") {
			continue
		}
		evt := parseViolationLine(line)
		if evt.Operation != "" {
			onViolation(evt)
		}
	}
}

// parseViolationLine extracts ViolationEvent from a sandbox log line.
func parseViolationLine(line string) ViolationEvent {
	evt := ViolationEvent{Timestamp: time.Now(), Raw: line}

	// Format: "process(12345) deny file-read-data /path" or "deny(1) file-read-data /path"
	// Try to extract operation (e.g. file-read-data, network-outbound) and path
	parts := strings.Fields(line)
	for i, p := range parts {
		if p == "deny" && i+1 < len(parts) {
			evt.Operation = parts[i+1]
			if i+2 < len(parts) {
				evt.Path = parts[i+2]
			}
			break
		}
		if strings.HasPrefix(p, "deny(") && i+1 < len(parts) {
			evt.Operation = parts[i+1]
			if i+2 < len(parts) {
				evt.Path = parts[i+2]
			}
			break
		}
	}

	// Fallback: use regex
	if evt.Operation == "" {
		if m := violationLineRegex.FindStringSubmatch(line); len(m) >= 3 {
			evt.Operation = m[1]
			evt.Path = m[2]
			if len(m) >= 4 {
				evt.Path = m[2] + " " + m[3]
			}
		}
	}

	return evt
}
