//go:build linux

package platform

import "github.com/bpicori/red-keep/internal/profile"

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

// New returns the Platform implementation for Linux.
func New() (Platform, error) {
	return &linuxPlatform{}, nil
}

func (l *linuxPlatform) SensitivePaths() []string {
	return linuxSensitivePaths
}

func (l *linuxPlatform) GenerateProfile(p *profile.Profile) (string, error) {
	// TODO: not yet implemented
	return "", nil
}

func (l *linuxPlatform) Exec(p *profile.Profile, onViolation ViolationHandler) (int, error) {
	// TODO: not yet implemented
	return 0, nil
}
