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
		want := `(deny file-read-data file-write-data (subpath "` + sp + `"))`
		if !strings.Contains(sbpl, want) {
			t.Errorf("profile missing sensitive path deny rule for %s", sp)
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
