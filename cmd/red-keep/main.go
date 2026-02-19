package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bpicori/red-keep/internal/cli"
	"github.com/bpicori/red-keep/internal/platform"
)

func main() {
	var showHelp bool
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showHelp, "h", false, "Show help message (shorthand)")

	flag.Usage = printUsage
	flag.Parse()

	if showHelp {
		printUsage()
		return
	}

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		os.Exit(2)
	}

	switch args[0] {
	case "run":
		os.Exit(cli.RunCmd(args[1:]))
	case "__redkeep_internal_linux_exec":
		plat, err := platform.New()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		exitCode, err := plat.RunInternalSandboxExec(args[1:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(exitCode)
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args[0])
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `red-keep - Deny-by-default sandbox for AI agents

Usage:
  red-keep <command> [options]

Commands:
  run       Run a command inside a sandbox
  help      Show this help message

Supported platforms: macOS (Seatbelt), Linux (Landlock + seccomp)

Run "red-keep run --help" for details on the run command.
`)
}
