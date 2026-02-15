package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSensitivePaths is used by tests. Matches paths rejected on darwin/linux.
// Includes both /etc and /private/etc forms since macOS resolves /etc to /private/etc.
var testSensitivePaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/private/etc/shadow",
	"/private/etc/passwd",
	"/private/etc/sudoers",
	"/private/etc",
	"/var/run/secrets",
	"/etc",
	"/System/Library",
	"/Library/Keychains",
}

func TestValidate_EmptyCommand(t *testing.T) {
	p := &Profile{}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for empty command")
	}
	if !strings.Contains(err.Error(), "command must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_MinimalValid(t *testing.T) {
	p := &Profile{
		Command: []string{"echo", "hello"},
	}
	if err := p.Validate(testSensitivePaths); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_RelativePath(t *testing.T) {
	p := &Profile{
		Command:   []string{"ls"},
		ReadPaths: []string{"relative/path"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for relative path")
	}
	if !strings.Contains(err.Error(), "path must be absolute") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_ControlCharInPath(t *testing.T) {
	p := &Profile{
		Command:   []string{"ls"},
		ReadPaths: []string{"/tmp/evil\x00path"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for control character in path")
	}
	if !strings.Contains(err.Error(), "control character") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_DotDotPath(t *testing.T) {
	p := &Profile{
		Command:    []string{"ls"},
		WritePaths: []string{"/tmp/../etc/shadow"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for '..' in path")
	}
}

func TestValidate_SensitivePath(t *testing.T) {
	for _, sp := range []string{"/etc/shadow", "/etc/passwd", "/var/run/secrets"} {
		p := &Profile{
			Command:   []string{"cat"},
			ReadPaths: []string{sp},
		}
		err := p.Validate(testSensitivePaths)
		if err == nil {
			t.Fatalf("expected error for sensitive path %q", sp)
		}
		if !strings.Contains(err.Error(), "sensitive path") {
			t.Fatalf("unexpected error for %q: %v", sp, err)
		}
	}
}

func TestValidate_SensitiveChildPath(t *testing.T) {
	p := &Profile{
		Command:   []string{"cat"},
		ReadPaths: []string{"/etc/shadow/subdir"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for child of sensitive path")
	}
	if !strings.Contains(err.Error(), "sensitive path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_SensitiveParentPath(t *testing.T) {
	// Granting access to a parent of a sensitive path should also be rejected,
	// since it would transitively expose the sensitive path.
	p := &Profile{
		Command:   []string{"ls"},
		ReadPaths: []string{"/etc"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for parent of sensitive path")
	}
}

func TestValidate_ValidAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	p := &Profile{
		Command:   []string{"ls"},
		ReadPaths: []string{dir},
	}
	if err := p.Validate(testSensitivePaths); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_WorkDirNotDirectory(t *testing.T) {
	f, err := os.CreateTemp("", "red-keep-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.Close()

	p := &Profile{
		Command: []string{"ls"},
		WorkDir: f.Name(),
	}
	err = p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for non-directory work dir")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_WorkDirDoesNotExist(t *testing.T) {
	p := &Profile{
		Command: []string{"ls"},
		WorkDir: "/nonexistent-dir-red-keep-test",
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for nonexistent work dir")
	}
}

func TestValidate_WorkDirValid(t *testing.T) {
	dir := t.TempDir()
	p := &Profile{
		Command: []string{"ls"},
		WorkDir: dir,
	}
	if err := p.Validate(testSensitivePaths); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_AllowNetWithDomains(t *testing.T) {
	p := &Profile{
		Command:      []string{"curl", "https://example.com"},
		AllowNet:     true,
		AllowDomains: []string{"example.com"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error combining --allow-net with --allow-domain")
	}
	if !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_AllowNetWithDenyDomains(t *testing.T) {
	p := &Profile{
		Command:     []string{"curl", "https://example.com"},
		AllowNet:    true,
		DenyDomains: []string{"evil.com"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error combining --allow-net with --deny-domain")
	}
}

func TestValidate_DomainsWithoutNet(t *testing.T) {
	p := &Profile{
		Command:      []string{"curl", "https://example.com"},
		AllowDomains: []string{"example.com"},
	}
	if err := p.Validate(testSensitivePaths); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_DomainWithScheme(t *testing.T) {
	p := &Profile{
		Command:      []string{"curl", "https://example.com"},
		AllowDomains: []string{"https://example.com"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for domain with URL scheme")
	}
	if !strings.Contains(err.Error(), "not a URL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_DomainWithPath(t *testing.T) {
	p := &Profile{
		Command:     []string{"curl", "https://example.com"},
		DenyDomains: []string{"example.com/path"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for domain with path")
	}
	if !strings.Contains(err.Error(), "not a URL path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_DomainEmpty(t *testing.T) {
	p := &Profile{
		Command:      []string{"curl", "https://example.com"},
		AllowDomains: []string{""},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
	if !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_DomainWildcardValid(t *testing.T) {
	p := &Profile{
		Command:      []string{"curl", "https://example.com"},
		AllowDomains: []string{"*.example.com"},
	}
	if err := p.Validate(testSensitivePaths); err != nil {
		t.Fatalf("unexpected error for wildcard domain: %v", err)
	}
}

func TestValidate_AllowAndDenyDomainsCombined(t *testing.T) {
	p := &Profile{
		Command:      []string{"curl", "https://example.com"},
		AllowDomains: []string{"example.com"},
		DenyDomains:  []string{"evil.com"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error combining --allow-domain with --deny-domain")
	}
	if !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_SymlinkResolution(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")

	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	// Resolve the target path the same way the OS does, since /var may be
	// a symlink to /private/var on macOS.
	resolvedTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}

	p := &Profile{
		Command:   []string{"ls"},
		ReadPaths: []string{link},
	}
	if err := p.Validate(testSensitivePaths); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// After validation, the path should be resolved to the real target.
	if p.ReadPaths[0] != resolvedTarget {
		t.Fatalf("expected resolved path %q, got %q", resolvedTarget, p.ReadPaths[0])
	}
}

func TestValidate_MultipleErrors(t *testing.T) {
	p := &Profile{
		// No command, relative read path, sensitive write path.
		ReadPaths:  []string{"relative"},
		WritePaths: []string{"/etc/shadow"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected errors")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "command must not be empty") {
		t.Fatalf("missing command error in: %v", errStr)
	}
	if !strings.Contains(errStr, "path must be absolute") {
		t.Fatalf("missing absolute-path error in: %v", errStr)
	}
	if !strings.Contains(errStr, "sensitive path") {
		t.Fatalf("missing sensitive-path error in: %v", errStr)
	}
}

func TestValidate_RWPathsValidated(t *testing.T) {
	p := &Profile{
		Command: []string{"ls"},
		RWPaths: []string{"not/absolute"},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for relative rw path")
	}
	if !strings.Contains(err.Error(), "rw path") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_EmptyPath(t *testing.T) {
	p := &Profile{
		Command:   []string{"ls"},
		ReadPaths: []string{""},
	}
	err := p.Validate(testSensitivePaths)
	if err == nil {
		t.Fatal("expected error for empty path")
	}
	if !strings.Contains(err.Error(), "path must not be empty") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPathOverlaps(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"/etc/shadow", "/etc/shadow", true},
		{"/etc/shadow", "/etc/shadow/sub", true},
		{"/etc", "/etc/shadow", true},
		{"/etc/shadow", "/etc", true},
		{"/tmp", "/etc", false},
		{"/tmp/foo", "/tmp/foobar", false}, // not a directory prefix
		{"/tmp/foo", "/tmp/foo/bar", true},
	}
	for _, tt := range tests {
		got := pathOverlaps(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("pathOverlaps(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestValidate_NonexistentPathStillValidates(t *testing.T) {
	// Paths that don't exist yet (e.g., write targets) should pass
	// validation as long as they're absolute and not sensitive.
	p := &Profile{
		Command:    []string{"touch"},
		WritePaths: []string{"/tmp/nonexistent-red-keep-test-dir/file.txt"},
	}
	if err := p.Validate(testSensitivePaths); err != nil {
		t.Fatalf("unexpected error for nonexistent write target: %v", err)
	}
}
