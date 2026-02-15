package platform

import (
	"time"

	"github.com/bpicori/red-keep/internal/profile"
)

// ViolationEvent represents a sandbox violation reported by the platform.
type ViolationEvent struct {
	Timestamp time.Time
	Operation string // e.g. "file-read-data", "network-outbound"
	Path      string // affected path or address
	Raw       string // raw platform log line
}

// ViolationHandler is called when a sandbox violation occurs.
type ViolationHandler func(ViolationEvent)

// Platform abstracts OS-specific sandbox behaviour.
type Platform interface {
	// SensitivePaths returns paths that must never be granted sandbox access
	// on this platform. Used during profile validation.
	SensitivePaths() []string

	// GenerateProfile returns the platform-specific sandbox profile as a string
	// (e.g., SBPL for macOS or Landlock for Linux). Used by --show-profile.
	GenerateProfile(p *profile.Profile) (string, error)

	// Exec runs the command in the sandbox. If onViolation is non-nil, violation
	// events are streamed through it. Returns the process exit code.
	Exec(p *profile.Profile, onViolation ViolationHandler) (int, error)
}

