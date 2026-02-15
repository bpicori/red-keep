//go:build darwin

package platform

import "github.com/bpicori/red-keep/internal/profile"

// darwinSensitivePaths lists paths that must never be granted sandbox access
// on macOS. Any user-provided path that overlaps with these is rejected.
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
	"/System/Library",
	"/Library/Keychains",
	"/Network",
}

type darwinPlatform struct{}

// New returns the Platform implementation for macOS.
func New() (Platform, error) {
	return &darwinPlatform{}, nil
}

func (d *darwinPlatform) SensitivePaths() []string {
	return darwinSensitivePaths
}

func (d *darwinPlatform) GenerateProfile(p *profile.Profile) (string, error) {
	// TODO: implement SBPL generation
	return "", nil
}

func (d *darwinPlatform) Exec(p *profile.Profile, onViolation ViolationHandler) (int, error) {
	// TODO: implement sandbox-exec
	return 0, nil
}
