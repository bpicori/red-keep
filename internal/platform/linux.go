//go:build linux

package platform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bpicori/red-keep/internal/profile"
	"github.com/bpicori/red-keep/internal/proxy"
	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/landlock-lsm/go-landlock/landlock"
	landlocksys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// linuxSensitivePaths lists paths that must never be granted sandbox access
// on Linux. Any user-provided path that overlaps with these is rejected.
var linuxSensitivePaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/var/run/secrets",
	"/boot",
	"/proc/kcore",
}

type linuxPlatform struct{}

const InternalLinuxPayloadEnv = "RED_KEEP_INTERNAL_LINUX_PAYLOAD"

// New returns the Platform implementation for Linux.
func New() (Platform, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return &linuxPlatform{}, nil
}

func (l *linuxPlatform) SensitivePaths() []string {
	return linuxSensitivePaths
}

func (l *linuxPlatform) GenerateProfile(p *profile.Profile) (string, error) {
	var sb strings.Builder
	sb.WriteString("# red-keep linux profile\n")
	sb.WriteString("engine=landlock+seccomp\n")
	sb.WriteString("default=deny\n")

	if p.AllowExec {
		sb.WriteString("process.fork=allow\n")
	} else {
		sb.WriteString("process.fork=deny\n")
	}

	if p.AllowPTY {
		sb.WriteString("pty=allow\n")
	} else {
		sb.WriteString("pty=deny\n")
	}

	switch {
	case p.AllowNet:
		sb.WriteString("network=allow\n")
	case hasDomainFilters(p):
		sb.WriteString("network=filtered-proxy\n")
		if len(p.AllowDomains) > 0 {
			sb.WriteString("network.mode=allowlist\n")
		}
		if len(p.DenyDomains) > 0 {
			sb.WriteString("network.mode=denylist\n")
		}
	default:
		sb.WriteString("network=deny\n")
	}

	sb.WriteString("sensitive_paths=deny\n")
	writeLinuxPathList(&sb, "allow.read", p.ReadPaths)
	writeLinuxPathList(&sb, "allow.write", p.WritePaths)
	writeLinuxPathList(&sb, "allow.rw", p.RWPaths)

	if p.WorkDir != "" {
		sb.WriteString("workdir=" + p.WorkDir + "\n")
	}

	tmpDir := os.TempDir()
	if tmpDir != "" {
		if resolved, err := filepath.EvalSymlinks(tmpDir); err == nil {
			tmpDir = resolved
		}
		sb.WriteString("allow.temp=" + tmpDir + "\n")
	}

	return sb.String(), nil
}

func (l *linuxPlatform) Exec(p *profile.Profile, opts ExecOptions) (int, error) {
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
			_ = prx.Stop(ctx)
		}()
	}

	payload := linuxExecPayload{
		Profile: *p,
	}

	encodedPayload, err := encodeLinuxExecPayload(payload)
	if err != nil {
		return -1, fmt.Errorf("encode internal linux payload: %w", err)
	}

	exePath := opts.HelperBinaryPath
	if exePath == "" {
		exePath, err = os.Executable()
		if err != nil {
			return -1, fmt.Errorf("resolve executable path: %w", err)
		}
	}

	ctx := opts.Context
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, exePath, "__redkeep_internal_linux_exec")
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
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	baseEnv := os.Environ()
	if len(opts.Env) > 0 {
		baseEnv = append([]string{}, opts.Env...)
	}
	cmd.Env = append(baseEnv, InternalLinuxPayloadEnv+"="+encodedPayload)
	if proxyAddr != "" {
		cmd.Env = proxyEnvWithBase(cmd.Env, proxyAddr)
	}

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start internal linux sandbox: %w", err)
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
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
		}
		return -1, waitErr
	}

	return 0, nil
}

// RunInternalSandboxExec applies Linux sandboxing and execs the target
// command. It is intentionally reachable only through the internal trampoline.
func (l *linuxPlatform) RunInternalSandboxExec(_ []string) (int, error) {
	payload, err := decodeLinuxExecPayload(os.Getenv(InternalLinuxPayloadEnv))
	if err != nil {
		return 1, err
	}

	p := &payload.Profile
	if len(p.Command) == 0 {
		return 1, fmt.Errorf("internal linux payload has empty command")
	}

	if err := setNoNewPrivs(); err != nil {
		return 1, fmt.Errorf("set no_new_privs: %w", err)
	}

	if err := applyLandlock(p); err != nil {
		return 1, fmt.Errorf("apply landlock: %w", err)
	}

	if err := applySeccomp(p); err != nil {
		return 1, fmt.Errorf("apply seccomp: %w", err)
	}

	if p.WorkDir != "" {
		if err := os.Chdir(p.WorkDir); err != nil {
			return 1, fmt.Errorf("chdir %q: %w", p.WorkDir, err)
		}
	}

	cmdPath, err := resolveCommandPath(p.Command[0])
	if err != nil {
		return 1, fmt.Errorf("resolve command %q: %w", p.Command[0], err)
	}

	if err := syscall.Exec(cmdPath, p.Command, os.Environ()); err != nil {
		return 1, fmt.Errorf("exec %q: %w", cmdPath, err)
	}
	return 0, nil
}

func hasDomainFilters(p *profile.Profile) bool {
	return len(p.AllowDomains) > 0 || len(p.DenyDomains) > 0
}

func writeLinuxPathList(sb *strings.Builder, label string, paths []string) {
	for _, path := range paths {
		sb.WriteString(label + "=" + path + "\n")
	}
}

type linuxExecPayload struct {
	Profile profile.Profile `json:"profile"`
}

func encodeLinuxExecPayload(payload linuxExecPayload) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func decodeLinuxExecPayload(encoded string) (linuxExecPayload, error) {
	var payload linuxExecPayload

	if encoded == "" {
		return payload, errors.New("missing RED_KEEP_INTERNAL_LINUX_PAYLOAD")
	}

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return payload, fmt.Errorf("decode payload: %w", err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, fmt.Errorf("unmarshal payload: %w", err)
	}

	return payload, nil
}

// proxyEnvWithBase returns environment with proxy vars set.
// Existing proxy vars are removed first, then replaced.
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

func resolveCommandPath(command string) (string, error) {
	if strings.Contains(command, "/") {
		return command, nil
	}
	return exec.LookPath(command)
}

// setNoNewPrivs prevents this process and descendants from gaining privileges
// via setuid/setgid binaries or file capabilities after sandbox setup starts.
func setNoNewPrivs() error {
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

// applyLandlock applies filesystem access rules using Landlock API.
func applyLandlock(p *profile.Profile) error {
	rules := buildLandlockRules(p)
	if len(rules) == 0 {
		return fmt.Errorf("landlock rule set is empty")
	}

	cfg, err := selectLandlockConfig()
	if err != nil {
		return err
	}

	// Fail-closed policy: require supported Landlock ABI on this kernel.
	if err := cfg.RestrictPaths(rules...); err != nil {
		// Normalize kernel capability errors to the message expected by diagnostics/integration checks.
		if strings.Contains(err.Error(), "missing kernel Landlock support") ||
			strings.Contains(err.Error(), "landlock is not supported") {
			return fmt.Errorf("landlock unavailable on this kernel (%w)", err)
		}
		return err
	}
	return nil
}

func selectLandlockConfig() (landlock.Config, error) {
	abi, err := landlocksys.LandlockGetABIVersion()
	if err != nil {
		return landlock.Config{}, fmt.Errorf("landlock unavailable on this kernel (%w)", err)
	}

	switch {
	case abi >= 7:
		return landlock.V7, nil
	case abi == 6:
		return landlock.V6, nil
	case abi == 5:
		return landlock.V5, nil
	case abi == 4:
		return landlock.V4, nil
	case abi == 3:
		return landlock.V3, nil
	case abi == 2:
		return landlock.V2, nil
	case abi == 1:
		return landlock.V1, nil
	default:
		return landlock.Config{}, fmt.Errorf("landlock unavailable on this kernel (unsupported ABI v%d)", abi)
	}
}

func buildLandlockRules(p *profile.Profile) []landlock.Rule {
	systemReadPaths := []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
		"/lib", "/lib64", "/etc/ld.so.cache", "/etc/ld.so.preload",
		"/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/localtime",
		"/etc/ssl", "/usr/share/zoneinfo", "/proc", "/sys/devices/system/cpu",
		"/dev/urandom",
	}

	rules := make([]landlock.Rule, 0, len(systemReadPaths)+len(p.ReadPaths)+len(p.WritePaths)+len(p.RWPaths)+8)

	appendPathRule := func(path string, readOnly bool) {
		target := nearestExistingPath(path)
		info, err := os.Stat(target)
		if err != nil {
			return
		}
		if info.IsDir() {
			if readOnly {
				rules = append(rules, landlock.RODirs(target))
			} else {
				rules = append(rules, landlock.RWDirs(target))
			}
			return
		}
		if readOnly {
			rules = append(rules, landlock.ROFiles(target))
		} else {
			rules = append(rules, landlock.RWFiles(target))
		}
	}

	for _, path := range systemReadPaths {
		appendPathRule(path, true)
	}

	// Many tools rely on writing to /dev/null (e.g. curl -o /dev/null).
	appendPathRule("/dev/null", false)

	if len(p.Command) > 0 {
		if resolved, err := resolveCommandPath(p.Command[0]); err == nil {
			appendPathRule(resolved, true)
		}
	}

	for _, path := range p.ReadPaths {
		appendPathRule(path, true)
	}
	for _, path := range p.WritePaths {
		appendPathRule(path, false)
	}
	for _, path := range p.RWPaths {
		appendPathRule(path, false)
	}

	tmpDir := os.TempDir()
	if tmpDir != "" {
		if resolved, err := filepath.EvalSymlinks(tmpDir); err == nil {
			tmpDir = resolved
		}
		appendPathRule(tmpDir, false)
	}

	if p.WorkDir != "" {
		appendPathRule(p.WorkDir, false)
	}

	if p.AllowPTY {
		appendPathRule("/dev/pts", false)
		appendPathRule("/dev/ptmx", false)
	}

	return rules
}

func nearestExistingPath(path string) string {
	cleaned := filepath.Clean(path)
	for {
		if cleaned == "." || cleaned == "" {
			return "/"
		}
		if _, err := os.Stat(cleaned); err == nil {
			return cleaned
		}
		if cleaned == "/" {
			return "/"
		}
		cleaned = filepath.Dir(cleaned)
	}
}

func applySeccomp(p *profile.Profile) error {
	denyNames := make(map[string]struct{})

	if !p.AllowExec {
		addSyscalls(denyNames, "clone", "fork", "vfork")
	}

	// Full deny-network mode blocks socket operations.
	// Filtered mode currently relies on proxy environment wiring and therefore
	// keeps socket syscalls available.
	if !p.AllowNet && !hasDomainFilters(p) {
		addSyscalls(denyNames,
			"socket", "socketpair", "connect", "bind",
			"listen", "accept", "accept4", "sendto",
			"sendmsg", "sendmmsg", "recvfrom", "recvmsg",
			"recvmmsg", "shutdown", "getsockopt",
			"setsockopt", "getsockname", "getpeername",
		)
	}

	return applySeccompDenyList(denyNames)
}

func addSyscalls(m map[string]struct{}, syscalls ...string) {
	for _, name := range syscalls {
		m[name] = struct{}{}
	}
}

func applySeccompDenyList(deny map[string]struct{}) error {
	policy := seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
	}

	if len(deny) == 0 {
		// Library policies must include at least one syscall group.
		// Keep seccomp installation active (fail-closed on unsupported kernels)
		// while producing a no-op allow-all policy.
		policy.Syscalls = append(policy.Syscalls, seccomp.SyscallGroup{
			Names:  []string{"read"},
			Action: seccomp.ActionAllow,
		})
	} else {
		names := make([]string, 0, len(deny))
		for name := range deny {
			names = append(names, name)
		}

		policy.Syscalls = append(policy.Syscalls, seccomp.SyscallGroup{
			Names:  names,
			Action: seccomp.Action(uint32(seccomp.ActionErrno) | uint32(syscall.EPERM)),
		})
	}

	filter := seccomp.Filter{
		NoNewPrivs: false,
		Flag:       seccomp.FilterFlagTSync,
		Policy:     policy,
	}

	if err := seccomp.LoadFilter(filter); err != nil {
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
			return fmt.Errorf("seccomp unavailable on this kernel (%w)", err)
		}
		return err
	}
	return nil
}
