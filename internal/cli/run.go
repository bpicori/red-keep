package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
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

// RunCmd executes the "run" subcommand which runs a command inside
// a sandbox with the specified capabilities.
func RunCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)

	var readPaths multiFlag
	var writePaths multiFlag
	var rwPaths multiFlag
	var allowDomains multiFlag
	var denyDomains multiFlag

	fs.Var(&readPaths, "allow-read", "Allow read access to path (can be specified multiple times)")
	fs.Var(&writePaths, "allow-write", "Allow write access to path (can be specified multiple times)")
	fs.Var(&rwPaths, "allow-rw", "Allow read-write access to path (can be specified multiple times)")
	fs.Var(&allowDomains, "allow-domain", "Allow network access to domain (enables filtered mode, can repeat, supports *.example.com)")
	fs.Var(&denyDomains, "deny-domain", "Deny network access to domain (enables filtered mode, can repeat, supports *.example.com)")

	_ = fs.Bool("allow-net", false, "Allow all network access (overrides domain filters)")
	_ = fs.Bool("allow-exec", false, "Allow spawning child processes")
	_ = fs.Bool("allow-pty", false, "Allow pseudo-terminal allocation")
	_ = fs.Bool("show-profile", false, "Print the generated sandbox profile and exit (do not run)")
	_ = fs.Bool("monitor", false, "Stream sandbox violation events to stderr")
	_ = fs.String("dir", "", "Working directory for the sandboxed command")

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
		return 2
	}

	// Everything after "--" (or remaining args) is the command.
	remaining := fs.Args()
	if len(remaining) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no command specified\n\n")
		fs.Usage()
		return 2
	}

	return 0
}
