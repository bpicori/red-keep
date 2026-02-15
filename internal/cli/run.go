package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bpicori/red-keep/internal/platform"
	"github.com/bpicori/red-keep/internal/profile"
)

// multiFlag is a flag.Value that accumulates multiple string values.
type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// runFlags holds the raw values parsed from the "run" subcommand flags.
type runFlags struct {
	readPaths    multiFlag
	writePaths   multiFlag
	rwPaths      multiFlag
	allowDomains multiFlag
	denyDomains  multiFlag
	allowNet     bool
	allowExec    bool
	allowPTY     bool
	showProfile  bool
	monitor      bool
	workDir      string
	command      []string
}

// parseRunFlags parses CLI arguments for the "run" subcommand.
func parseRunFlags(args []string) (*runFlags, int) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)

	f := &runFlags{}

	fs.Var(&f.readPaths, "allow-read", "Allow read access to path (can be specified multiple times)")
	fs.Var(&f.writePaths, "allow-write", "Allow write access to path (can be specified multiple times)")
	fs.Var(&f.rwPaths, "allow-rw", "Allow read-write access to path (can be specified multiple times)")
	fs.Var(&f.allowDomains, "allow-domain", "Allow network access to domain (enables filtered mode, can repeat, supports *.example.com)")
	fs.Var(&f.denyDomains, "deny-domain", "Deny network access to domain (enables filtered mode, can repeat, supports *.example.com)")

	fs.BoolVar(&f.allowNet, "allow-net", false, "Allow all network access (overrides domain filters)")
	fs.BoolVar(&f.allowExec, "allow-exec", false, "Allow spawning child processes")
	fs.BoolVar(&f.allowPTY, "allow-pty", false, "Allow pseudo-terminal allocation")
	fs.BoolVar(&f.showProfile, "show-profile", false, "Print the generated sandbox profile and exit (do not run)")
	fs.BoolVar(&f.monitor, "monitor", false, "Stream sandbox violation events to stderr")
	fs.StringVar(&f.workDir, "dir", "", "Working directory for the sandboxed command")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: red-keep run [options] -- <command> [args...]\n\n")
		fmt.Fprintf(os.Stderr, "Run a command inside a sandbox.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  red-keep run --allow-read /home/dev/project -- ls -la\n")
		fmt.Fprintf(os.Stderr, "  red-keep run --allow-rw /tmp/output --allow-net -- curl https://example.com -o /tmp/output/file\n")
		fmt.Fprintf(os.Stderr, "  red-keep run --allow-domain example.com --allow-domain '*.github.com' -- curl https://example.com\n")
		fmt.Fprintf(os.Stderr, "  red-keep run --deny-domain evil.com --deny-domain '*.malware.net' -- python agent.py\n")
		fmt.Fprintf(os.Stderr, "  red-keep run --show-profile --allow-read /home/dev -- echo test\n")
	}

	if err := fs.Parse(args); err != nil {
		return nil, 2
	}

	// Everything after "--" (or remaining args) is the command.
	f.command = fs.Args()
	if len(f.command) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no command specified\n\n")
		fs.Usage()
		return nil, 2
	}

	return f, 0
}

// buildProfile constructs a Profile from the parsed run flags.
func buildProfile(f *runFlags) *profile.Profile {
	return &profile.Profile{
		ReadPaths:    []string(f.readPaths),
		WritePaths:   []string(f.writePaths),
		RWPaths:      []string(f.rwPaths),
		AllowNet:     f.allowNet,
		AllowDomains: []string(f.allowDomains),
		DenyDomains:  []string(f.denyDomains),
		AllowExec:    f.allowExec,
		AllowPTY:     f.allowPTY,
		WorkDir:      f.workDir,
		ShowProfile:  f.showProfile,
		Monitor:      f.monitor,
		Command:      f.command,
	}
}

// RunCmd executes the "run" subcommand which runs a command inside
func RunCmd(args []string) int {
	f, exitCode := parseRunFlags(args)
	if f == nil {
		return exitCode
	}

	p := buildProfile(f)

	// Initialise the platform (darwin, linux, etc.).
	plat, err := platform.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	// Validate the profile against platform-specific sensitive paths.
	if err := p.Validate(plat.SensitivePaths()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid profile: %v\n", err)
		return 1
	}

	// --show-profile: print the generated sandbox profile and exit.
	if p.ShowProfile {
		sbpl, err := plat.GenerateProfile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: generate profile: %v\n", err)
			return 1
		}
		fmt.Print(sbpl)
		return 0
	}

	// Set up an optional violation handler for --monitor.
	var onViolation platform.ViolationHandler
	if p.Monitor {
		onViolation = func(evt platform.ViolationEvent) {
			fmt.Fprintf(os.Stderr, "[violation] %s %s (%s)\n", evt.Operation, evt.Path, evt.Raw)
		}
	}

	// Execute the command inside the sandbox.
	exitCode, err = plat.Exec(p, onViolation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	return exitCode
}
