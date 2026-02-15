package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bpicori/red-keep/internal/cli"
)

const version = "0.1.0"

func main() {
	var showHelp, showVersion bool
	flag.BoolVar(&showHelp, "help", false, "Show help message")
	flag.BoolVar(&showHelp, "h", false, "Show help message (shorthand)")
	flag.BoolVar(&showVersion, "version", false, "Print version information")
	flag.BoolVar(&showVersion, "v", false, "Print version information (shorthand)")

	flag.Usage = printUsage
	flag.Parse()

	if showHelp {
		printUsage()
		return
	}
	if showVersion {
		fmt.Printf("red-keep %s\n", version)
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
	case "version":
		fmt.Printf("red-keep %s\n", version)
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
  version   Print version information
  help      Show this help message

Supported platforms: macOS (Seatbelt), Linux (Landlock + seccomp) [planned]

Run "red-keep run --help" for details on the run command.
`)
}
