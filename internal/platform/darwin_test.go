//go:build darwin

package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpicori/red-keep/internal/profile"
)

func TestMain(m *testing.M) {
	// Ensure sandbox-exec is available before running integration tests.
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		// Not on macOS or sandbox-exec unavailable; skip all tests.
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// execSandbox is a test helper that validates a profile, generates the SBPL
// sandbox profile, writes it to a temp file, and runs sandbox-exec with the
// given command. It captures and returns stdout, stderr, and the exit code.
func execSandbox(t *testing.T, p *profile.Profile) (stdout, stderr string, exitCode int) {
	t.Helper()

	d := &darwinPlatform{}

	// Mirror the real flow: validate first (resolves symlinks in paths).
	if err := p.Validate(d.SensitivePaths()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}

	tmpFile, err := os.CreateTemp("", "red-keep-test-*.sb")
	if err != nil {
		t.Fatalf("create temp profile: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(sbpl); err != nil {
		tmpFile.Close()
		t.Fatalf("write profile: %v", err)
	}
	tmpFile.Close()

	args := append([]string{"-f", tmpFile.Name(), "--"}, p.Command...)
	cmd := exec.Command("sandbox-exec", args...)

	var stdoutBuf, stderrBuf strings.Builder
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	if p.WorkDir != "" {
		cmd.Dir = p.WorkDir
	}

	err = cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("sandbox-exec failed: %v", err)
		}
	}

	return stdoutBuf.String(), stderrBuf.String(), exitCode
}

// ---------------------------------------------------------------------------
// Basic execution
// ---------------------------------------------------------------------------

func TestExec_BasicEcho(t *testing.T) {
	p := &profile.Profile{
		Command: []string{"/bin/echo", "hello"},
	}
	stdout, _, exitCode := execSandbox(t, p)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if strings.TrimSpace(stdout) != "hello" {
		t.Fatalf("expected stdout %q, got %q", "hello", stdout)
	}
}

func TestExec_NonZeroExit(t *testing.T) {
	p := &profile.Profile{
		Command: []string{"/usr/bin/false"},
	}
	_, _, exitCode := execSandbox(t, p)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit code from /usr/bin/false")
	}
}

// ---------------------------------------------------------------------------
// File-system read access
// ---------------------------------------------------------------------------

func TestExec_ReadAllowed(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("sandbox-ok"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &profile.Profile{
		ReadPaths: []string{dir},
		Command:   []string{"/bin/cat", filePath},
	}
	stdout, stderr, exitCode := execSandbox(t, p)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", exitCode, stderr)
	}
	if strings.TrimSpace(stdout) != "sandbox-ok" {
		t.Fatalf("expected stdout %q, got %q", "sandbox-ok", stdout)
	}
}

func TestExec_ReadDenied(t *testing.T) {
	// Create a file outside TMPDIR so it is not covered by the temp dir rule.
	dir, err := os.MkdirTemp("/private/tmp", "red-keep-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	filePath := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(filePath, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := &profile.Profile{
		// No ReadPaths — dir is not allowed.
		Command: []string{"/bin/cat", filePath},
	}
	_, stderr, exitCode := execSandbox(t, p)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit when reading a denied path")
	}
	if !strings.Contains(stderr, "Operation not permitted") && !strings.Contains(stderr, "Permission denied") {
		t.Fatalf("expected permission error in stderr, got: %s", stderr)
	}
}

// ---------------------------------------------------------------------------
// File-system write access
// ---------------------------------------------------------------------------

func TestExec_WriteAllowed(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out.txt")

	p := &profile.Profile{
		AllowExec: true, // sh -c needs fork
		RWPaths:   []string{dir},
		Command:   []string{"/bin/sh", "-c", "echo written > " + outFile},
	}
	_, stderr, exitCode := execSandbox(t, p)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", exitCode, stderr)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "written" {
		t.Fatalf("expected file content %q, got %q", "written", string(data))
	}
}

func TestExec_WriteDenied(t *testing.T) {
	// Use a directory outside TMPDIR so the temp dir rule doesn't grant write.
	dir, err := os.MkdirTemp("/private/tmp", "red-keep-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	outFile := filepath.Join(dir, "out.txt")

	p := &profile.Profile{
		AllowExec: true,
		ReadPaths: []string{dir}, // read-only, no write
		Command:   []string{"/bin/sh", "-c", "echo nope > " + outFile},
	}
	_, _, exitCode := execSandbox(t, p)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit when writing to a read-only path")
	}
	if _, err := os.Stat(outFile); err == nil {
		t.Fatal("file should not have been created")
	}
}

// ---------------------------------------------------------------------------
// Bypass prevention (rename/unlink on sensitive paths)
// ---------------------------------------------------------------------------

func TestExec_RenameDenied(t *testing.T) {
	// mv from a sensitive path must be denied (prevents read bypass).
	tmpDir := t.TempDir()
	p := &profile.Profile{
		AllowExec: true,
		RWPaths:   []string{tmpDir},
		Command:   []string{"/bin/mv", "/private/etc/shells", tmpDir + "/shells"},
	}
	_, stderr, exitCode := execSandbox(t, p)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit when renaming from sensitive path")
	}
	if !strings.Contains(stderr, "Operation not permitted") && !strings.Contains(stderr, "Permission denied") {
		t.Errorf("expected permission error in stderr, got: %s", stderr)
	}
}

func TestExec_UnlinkDenied(t *testing.T) {
	// rm on a sensitive path must be denied (prevents write bypass).
	p := &profile.Profile{
		AllowExec: true,
		Command:   []string{"/bin/rm", "/private/etc/shells"},
	}
	_, stderr, exitCode := execSandbox(t, p)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit when unlinking sensitive path")
	}
	if !strings.Contains(stderr, "Operation not permitted") && !strings.Contains(stderr, "Permission denied") {
		t.Errorf("expected permission error in stderr, got: %s", stderr)
	}
}

func TestExec_RenameAncestorDenied(t *testing.T) {
	// Renaming a parent of a sensitive path must be denied (directory-swap attack).
	tmpDir := t.TempDir()
	p := &profile.Profile{
		AllowExec: true,
		RWPaths:   []string{tmpDir},
		Command:   []string{"/bin/mv", "/private/etc", tmpDir + "/etc_backup"},
	}
	_, stderr, exitCode := execSandbox(t, p)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit when renaming ancestor of sensitive path")
	}
	if !strings.Contains(stderr, "Operation not permitted") && !strings.Contains(stderr, "Permission denied") {
		t.Errorf("expected permission error in stderr, got: %s", stderr)
	}
}

// ---------------------------------------------------------------------------
// Process fork control (AllowExec)
// ---------------------------------------------------------------------------

func TestExec_ForkDenied(t *testing.T) {
	// A pipeline requires fork. Without AllowExec, fork is denied.
	p := &profile.Profile{
		AllowExec: false,
		Command:   []string{"/bin/sh", "-c", "echo a | cat"},
	}
	_, stderr, exitCode := execSandbox(t, p)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit when fork is denied")
	}
	if !strings.Contains(stderr, "fork") && !strings.Contains(stderr, "Operation not permitted") {
		t.Fatalf("expected fork error in stderr, got: %s", stderr)
	}
}

func TestExec_ForkAllowed(t *testing.T) {
	p := &profile.Profile{
		AllowExec: true,
		Command:   []string{"/bin/sh", "-c", "echo piped | /bin/cat"},
	}
	stdout, _, exitCode := execSandbox(t, p)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if strings.TrimSpace(stdout) != "piped" {
		t.Fatalf("expected stdout %q, got %q", "piped", stdout)
	}
}

// ---------------------------------------------------------------------------
// Network access
// ---------------------------------------------------------------------------

func TestExec_NetworkDenied(t *testing.T) {
	// curl should fail when network is denied.
	p := &profile.Profile{
		AllowExec: true,
		Command:   []string{"/usr/bin/curl", "-s", "--max-time", "2", "https://example.com"},
	}
	_, _, exitCode := execSandbox(t, p)
	if exitCode == 0 {
		t.Fatal("expected non-zero exit when network is denied")
	}
}

func TestExec_NetworkAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	p := &profile.Profile{
		AllowExec: true,
		AllowNet:  true,
		Command:   []string{"/usr/bin/curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "5", "https://example.com"},
	}
	stdout, stderr, exitCode := execSandbox(t, p)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s", exitCode, stderr)
	}
	if strings.TrimSpace(stdout) != "200" {
		t.Fatalf("expected HTTP 200, got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Working directory
// ---------------------------------------------------------------------------

func TestExec_WorkDir(t *testing.T) {
	dir := t.TempDir()

	p := &profile.Profile{
		WorkDir: dir,
		Command: []string{"/bin/pwd"},
	}
	stdout, _, exitCode := execSandbox(t, p)
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}

	// On macOS /tmp is a symlink to /private/tmp, so resolve both.
	got, _ := filepath.EvalSymlinks(strings.TrimSpace(stdout))
	want, _ := filepath.EvalSymlinks(dir)
	if got != want {
		t.Fatalf("expected cwd %q, got %q", want, got)
	}
}

// ---------------------------------------------------------------------------
// GenerateProfile content checks
// ---------------------------------------------------------------------------

func TestGenerateProfile_DefaultDeny(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		Command: []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(version 1)",
		"(deny default)",
		"(allow process-exec*)",
		"(deny process-fork)",
		"(deny network*)",
	} {
		if !strings.Contains(sbpl, want) {
			t.Errorf("profile missing %q", want)
		}
	}
}

func TestGenerateProfile_AllowExec(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		AllowExec: true,
		Command:   []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sbpl, "(allow process-fork)") {
		t.Error("profile should allow process-fork when AllowExec is true")
	}
	if strings.Contains(sbpl, "(deny process-fork)") {
		t.Error("profile should not deny process-fork when AllowExec is true")
	}
}

func TestGenerateProfile_AllowNet(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		AllowNet: true,
		Command:  []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(allow network-outbound)",
		"(allow network-inbound)",
		"(allow network-bind)",
	} {
		if !strings.Contains(sbpl, want) {
			t.Errorf("profile missing %q", want)
		}
	}
	if strings.Contains(sbpl, "(deny network*)") {
		t.Error("profile should not deny network when AllowNet is true")
	}
}

func TestGenerateProfile_ReadPaths(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		ReadPaths: []string{"/tmp/test-read"},
		Command:   []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sbpl, `(allow file-read* (subpath "/tmp/test-read"))`) {
		t.Errorf("profile missing read path rule, got:\n%s", sbpl)
	}
}

func TestGenerateProfile_WritePaths(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		WritePaths: []string{"/tmp/test-write"},
		Command:    []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sbpl, `(allow file-write* (subpath "/tmp/test-write"))`) {
		t.Errorf("profile missing write path rule, got:\n%s", sbpl)
	}
}

func TestGenerateProfile_RWPaths(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		RWPaths: []string{"/tmp/test-rw"},
		Command: []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sbpl, `(allow file-read* file-write* (subpath "/tmp/test-rw"))`) {
		t.Errorf("profile missing rw path rule, got:\n%s", sbpl)
	}
}

func TestGenerateProfile_SensitivePathsDenied(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		Command: []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, sp := range darwinSensitivePaths {
		want := `(deny file-read* file-write* (subpath "` + sp + `"))`
		if !strings.Contains(sbpl, want) {
			t.Errorf("profile missing sensitive path deny rule for %s", sp)
		}
	}
}

func TestPathAncestors(t *testing.T) {
	tests := []struct {
		path string
		want []string
	}{
		{"/private/etc/shadow", []string{"/private/etc", "/private"}},
		{"/System/Library", []string{"/System"}},
		{"/Library/Keychains", []string{"/Library"}},
		{"/private/var/db/dslocal", []string{"/private/var/db", "/private/var", "/private"}},
		{"/", nil},
		{"/single", nil}, // only ancestor is / which we exclude
	}
	for _, tt := range tests {
		got := pathAncestors(tt.path)
		if len(got) != len(tt.want) {
			t.Errorf("pathAncestors(%q) = %v, want %v", tt.path, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("pathAncestors(%q)[%d] = %q, want %q", tt.path, i, got[i], tt.want[i])
			}
		}
	}
}

func TestGenerateProfile_BypassPreventionAncestorDenies(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		Command: []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Must deny file-write* on ancestors to prevent directory-swap attacks.
	wantAncestors := []string{"/private", "/private/etc", "/private/var", "/private/var/db", "/private/var/run", "/System", "/Library"}
	for _, anc := range wantAncestors {
		want := `(deny file-write* (subpath "` + anc + `"))`
		if !strings.Contains(sbpl, want) {
			t.Errorf("profile missing ancestor deny rule for %s (bypass prevention)", anc)
		}
	}
}

func TestGenerateProfile_PTY(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		AllowPTY: true,
		Command:  []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sbpl, `(allow file-read* file-write* (subpath "/dev"))`) {
		t.Error("profile missing PTY dev rule")
	}
}

// ---------------------------------------------------------------------------
// Domain filtering profile generation
// ---------------------------------------------------------------------------

func TestGenerateProfile_AllowDomains(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		AllowDomains: []string{"example.com"},
		Command:      []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}

	// Should allow outbound only to localhost (proxy).
	if !strings.Contains(sbpl, `(allow network-outbound (remote ip "localhost:*"))`) {
		t.Error("profile missing localhost-only network-outbound rule")
	}

	// Should NOT allow unrestricted network.
	if strings.Contains(sbpl, "(allow network-outbound)\n") {
		t.Error("profile should not allow unrestricted network-outbound with domain filtering")
	}
	if strings.Contains(sbpl, "(allow network-inbound)") {
		t.Error("profile should not allow network-inbound with domain filtering")
	}
	if strings.Contains(sbpl, "(allow network-bind)") {
		t.Error("profile should not allow network-bind with domain filtering")
	}
	if strings.Contains(sbpl, "(deny network*)") {
		t.Error("profile should not deny all network with domain filtering")
	}

	// Should still allow SSL certs and resolver config.
	if !strings.Contains(sbpl, `(allow file-read* (subpath "/private/etc/ssl"))`) {
		t.Error("profile missing SSL certificate read rule")
	}
	if !strings.Contains(sbpl, `(allow file-read* (literal "/private/etc/resolv.conf"))`) {
		t.Error("profile missing resolv.conf read rule")
	}
}

func TestGenerateProfile_DenyDomains(t *testing.T) {
	d := &darwinPlatform{}
	p := &profile.Profile{
		DenyDomains: []string{"evil.com", "*.malware.net"},
		Command:     []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}

	// Should have localhost-only outbound (same as allowlist mode).
	if !strings.Contains(sbpl, `(allow network-outbound (remote ip "localhost:*"))`) {
		t.Error("profile missing localhost-only network-outbound rule")
	}
	if strings.Contains(sbpl, "(deny network*)") {
		t.Error("profile should not deny all network with deny-domain filtering")
	}
}

func TestGenerateProfile_DomainFilteringDoesNotAffectFullNet(t *testing.T) {
	// AllowNet should still produce unrestricted network rules.
	d := &darwinPlatform{}
	p := &profile.Profile{
		AllowNet: true,
		Command:  []string{"echo"},
	}
	sbpl, err := d.GenerateProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sbpl, "(allow network-outbound)\n") {
		t.Error("AllowNet should produce unrestricted network-outbound")
	}
	if strings.Contains(sbpl, `remote ip "localhost:*"`) {
		t.Error("AllowNet should not restrict to localhost")
	}
}
