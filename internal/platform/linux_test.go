//go:build linux

package platform

import (
	"strings"
	"testing"

	"github.com/bpicori/red-keep/internal/profile"
)

func TestLinuxSensitivePaths(t *testing.T) {
	l := &linuxPlatform{}
	paths := l.SensitivePaths()
	want := []string{
		"/etc/shadow",
		"/etc/passwd",
		"/etc/sudoers",
		"/var/run/secrets",
		"/boot",
		"/proc/kcore",
	}

	for _, expected := range want {
		if !contains(paths, expected) {
			t.Fatalf("SensitivePaths missing %q", expected)
		}
	}
}

func TestGenerateProfile_DefaultDeny(t *testing.T) {
	l := &linuxPlatform{}
	p := &profile.Profile{
		Command: []string{"/bin/echo", "ok"},
	}

	profileText, err := l.GenerateProfile(p)
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}

	for _, token := range []string{
		"engine=landlock+seccomp",
		"default=deny",
		"process.fork=deny",
		"network=deny",
		"pty=deny",
		"sensitive_paths=deny",
	} {
		if !strings.Contains(profileText, token) {
			t.Fatalf("missing token %q in profile:\n%s", token, profileText)
		}
	}
}

func TestGenerateProfile_AllowExecAndNet(t *testing.T) {
	l := &linuxPlatform{}
	p := &profile.Profile{
		AllowExec: true,
		AllowNet:  true,
		Command:   []string{"/bin/echo", "ok"},
	}

	profileText, err := l.GenerateProfile(p)
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}

	if !strings.Contains(profileText, "process.fork=allow") {
		t.Fatal("expected process.fork=allow")
	}
	if !strings.Contains(profileText, "network=allow") {
		t.Fatal("expected network=allow")
	}
	if strings.Contains(profileText, "network=deny") {
		t.Fatal("did not expect network=deny")
	}
}

func TestGenerateProfile_FilteredMode(t *testing.T) {
	l := &linuxPlatform{}
	p := &profile.Profile{
		AllowDomains: []string{"example.com"},
		Command:      []string{"/bin/echo", "ok"},
	}

	profileText, err := l.GenerateProfile(p)
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}

	if !strings.Contains(profileText, "network=filtered-proxy") {
		t.Fatal("expected filtered-proxy network mode")
	}
	if !strings.Contains(profileText, "network.mode=allowlist") {
		t.Fatal("expected allowlist network mode detail")
	}
}

func TestGenerateProfile_PathRules(t *testing.T) {
	l := &linuxPlatform{}
	p := &profile.Profile{
		ReadPaths:  []string{"/tmp/read"},
		WritePaths: []string{"/tmp/write"},
		RWPaths:    []string{"/tmp/rw"},
		Command:    []string{"/bin/echo", "ok"},
	}

	profileText, err := l.GenerateProfile(p)
	if err != nil {
		t.Fatalf("GenerateProfile: %v", err)
	}

	for _, token := range []string{
		"allow.read=/tmp/read",
		"allow.write=/tmp/write",
		"allow.rw=/tmp/rw",
	} {
		if !strings.Contains(profileText, token) {
			t.Fatalf("missing path token %q", token)
		}
	}
}

func TestEncodeDecodeLinuxExecPayload(t *testing.T) {
	encoded, err := encodeLinuxExecPayload(linuxExecPayload{
		Profile: profile.Profile{
			AllowExec: true,
			Command:   []string{"/bin/echo", "hello"},
		},
	})
	if err != nil {
		t.Fatalf("encodeLinuxExecPayload: %v", err)
	}

	decoded, err := decodeLinuxExecPayload(encoded)
	if err != nil {
		t.Fatalf("decodeLinuxExecPayload: %v", err)
	}

	if !decoded.Profile.AllowExec {
		t.Fatal("expected AllowExec=true")
	}
	if got := strings.Join(decoded.Profile.Command, " "); got != "/bin/echo hello" {
		t.Fatalf("unexpected command %q", got)
	}
}

func TestProxyEnvWithBase(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"HTTP_PROXY=http://old:1",
		"https_proxy=http://old:2",
	}
	env := proxyEnvWithBase(base, "127.0.0.1:18080")

	if !containsEnv(env, "HTTP_PROXY=http://127.0.0.1:18080") {
		t.Fatal("missing updated HTTP_PROXY")
	}
	if !containsEnv(env, "https_proxy=http://127.0.0.1:18080") {
		t.Fatal("missing updated https_proxy")
	}
	if containsEnv(env, "HTTP_PROXY=http://old:1") {
		t.Fatal("old HTTP_PROXY should be removed")
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func containsEnv(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}
