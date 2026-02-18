package platform

import "github.com/bpicori/red-keep/internal/profile"

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

	// RunInternalSandboxExec executes the internal sandbox entrypoint.
	// On Linux this applies kernel sandboxing before exec, and on
	// non-Linux platforms it is a no-op.
	RunInternalSandboxExec(args []string) (int, error)
}
