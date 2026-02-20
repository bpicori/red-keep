package redkeep

import (
	"context"
	"io"
)

// RunRequest describes a sandboxed command execution request.
type RunRequest struct {
	ReadPaths  []string
	WritePaths []string
	RWPaths    []string

	AllowNet     bool
	AllowDomains []string
	DenyDomains  []string

	AllowExec bool
	AllowPTY  bool

	WorkDir     string
	ShowProfile bool

	Command []string
}

// RunIO controls runtime IO/env behavior for command execution.
type RunIO struct {
	Context context.Context

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Env overrides the environment passed to the sandboxed process.
	// When empty, the current process environment is used.
	Env []string

	// HelperBinaryPath is used by Linux internal trampoline execution.
	// If empty, platform defaults apply.
	HelperBinaryPath string
}

// RunResult contains execution metadata.
type RunResult struct {
	ExitCode         int
	GeneratedProfile string
}
