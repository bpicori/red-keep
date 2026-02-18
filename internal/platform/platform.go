package platform

import (
	"fmt"

	"github.com/bpicori/red-keep/internal/profile"
)

// Platform abstracts OS-specific sandbox behaviour.
type Platform interface {
	// SensitivePaths returns paths that must never be granted sandbox access
	// on this platform. Used during profile validation.
	SensitivePaths() []string

	// GenerateProfile returns the platform-specific sandbox profile as a string
	// (e.g., SBPL for macOS or Landlock for Linux). Used by --show-profile.
	GenerateProfile(p *profile.Profile) (string, error)

	// Exec runs the command in the sandbox. Returns the process exit code.
	Exec(p *profile.Profile) (int, error)
}

var runInternalLinuxExec = func(_ []string) (int, error) {
	return 1, fmt.Errorf("internal linux exec is only supported on Linux")
}

// RunInternalLinuxExec executes the Linux-only internal trampoline.
func RunInternalLinuxExec(args []string) (int, error) {
	return runInternalLinuxExec(args)
}
