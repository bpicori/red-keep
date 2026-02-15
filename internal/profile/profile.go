package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Path validation errors. Use errors.Is to check for them.
var (
	ErrPathEmpty       = errors.New("path must not be empty")
	ErrPathControlChar = errors.New("path contains control character")
	ErrPathNotAbsolute = errors.New("path must be absolute")
	ErrPathDotDot      = errors.New("path must not contain '..' components")
	ErrPathSensitive   = errors.New("path overlaps with sensitive path")
)

// Profile holds the parsed, validated sandbox configuration.
// It is platform-agnostic; platform-specific code translates it into
type Profile struct {
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
	Monitor     bool

	Command []string
}

// Validate checks the profile for logical consistency and ensures all
// paths are absolute, resolvable, and do not overlap with the given sensitive
// system paths. sensitivePaths is platform-specific (e.g. from Platform.SensitivePaths()).
// It returns a combined error of every issue found.
func (p *Profile) Validate(sensitivePaths []string) error {
	var errs []error

	if len(p.Command) == 0 {
		errs = append(errs, errors.New("command must not be empty"))
	}

	if p.WorkDir != "" {
		resolved, err := resolveAndValidatePath(p.WorkDir, sensitivePaths)
		if err != nil {
			errs = append(errs, fmt.Errorf("work dir %q: %w", p.WorkDir, err))
		} else {
			p.WorkDir = resolved
			info, err := os.Stat(resolved)
			if err != nil {
				errs = append(errs, fmt.Errorf("work dir %q: %w", resolved, err))
			} else if !info.IsDir() {
				errs = append(errs, fmt.Errorf("work dir %q is not a directory", resolved))
			}
		}
	}

	p.ReadPaths, errs = validatePaths(p.ReadPaths, "read path", sensitivePaths, errs)
	p.WritePaths, errs = validatePaths(p.WritePaths, "write path", sensitivePaths, errs)
	p.RWPaths, errs = validatePaths(p.RWPaths, "rw path", sensitivePaths, errs)

	// Validate domain format (must be hostnames, not URLs).
	for _, d := range p.AllowDomains {
		if err := validateDomain(d); err != nil {
			errs = append(errs, fmt.Errorf("--allow-domain %q: %w", d, err))
		}
	}
	for _, d := range p.DenyDomains {
		if err := validateDomain(d); err != nil {
			errs = append(errs, fmt.Errorf("--deny-domain %q: %w", d, err))
		}
	}

	// Domain flags are only valid when AllowNet is false (filtered mode).
	if p.AllowNet && (len(p.AllowDomains) > 0 || len(p.DenyDomains) > 0) {
		errs = append(errs, errors.New("--allow-net cannot be combined with --allow-domain or --deny-domain"))
	}

	// Allowlist and denylist are mutually exclusive to avoid ambiguous semantics.
	if len(p.AllowDomains) > 0 && len(p.DenyDomains) > 0 {
		errs = append(errs, errors.New("--allow-domain and --deny-domain cannot be combined"))
	}

	return errors.Join(errs...)
}

func validatePaths(paths []string, label string, sensitivePaths []string, errs []error) ([]string, []error) {
	resolved := make([]string, 0, len(paths))
	for _, p := range paths {
		r, err := resolveAndValidatePath(p, sensitivePaths)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %q: %w", label, p, err))
			continue
		}
		resolved = append(resolved, r)
	}
	return resolved, errs
}

// resolveAndValidatePath ensures a path is absolute, resolves symlinks, and validates the path
func resolveAndValidatePath(raw string, sensitivePaths []string) (string, error) {
	if raw == "" {
		return "", ErrPathEmpty
	}

	// Reject control characters, like null bytes or backspace, tabs etc.
	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("%w (0x%02x)", ErrPathControlChar, c)
		}
	}

	if !filepath.IsAbs(raw) {
		return "", ErrPathNotAbsolute
	}

	// Clean the path and reject remaining ".." components.
	cleaned := filepath.Clean(raw)
	if slices.Contains(strings.Split(cleaned, string(filepath.Separator)), "..") {
		return "", ErrPathDotDot
	}

	// check if the path is a symlink, and if so, resolve it, if is not a symlink, it will use the same path
	// if it fails to resolve the symlink, it will use the same path
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		resolved = cleaned
	}

	if err := checkSensitivePath(resolved, sensitivePaths); err != nil {
		return "", err
	}

	return resolved, nil
}

// checkSensitivePath returns an error if the given resolved path equals
// or is a child of any entry in sensitivePaths.
func checkSensitivePath(resolved string, sensitivePaths []string) error {
	for _, sensitive := range sensitivePaths {
		if pathOverlaps(resolved, sensitive) {
			return fmt.Errorf("%w %q", ErrPathSensitive, sensitive)
		}
	}
	return nil
}

// validateDomain checks that d is a bare hostname (with optional wildcard
// prefix), not a URL or path. This catches mistakes like passing
// "https://example.com" instead of "example.com".
func validateDomain(d string) error {
	if d == "" {
		return errors.New("domain must not be empty")
	}
	if strings.Contains(d, "://") {
		return errors.New("must be a domain name, not a URL (remove the scheme)")
	}
	if strings.Contains(d, "/") {
		return errors.New("must be a domain name, not a URL path")
	}
	if strings.Contains(d, " ") {
		return errors.New("domain must not contain spaces")
	}
	return nil
}

// pathOverlaps reports whether a and b are equal, or one is a prefix
// example: /etc/shadow and /etc/shadow/subdir are overlapping
func pathOverlaps(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)

	if a == b {
		return true
	}

	aSlash := a + string(filepath.Separator)
	bSlash := b + string(filepath.Separator)
	return strings.HasPrefix(aSlash, bSlash) || strings.HasPrefix(bSlash, aSlash)
}
