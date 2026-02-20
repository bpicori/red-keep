package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bpicori/red-keep/pkg/redkeep"
	"gopkg.in/yaml.v3"
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

// boolFlag is a flag.Value that tracks whether it was explicitly set.
type boolFlag struct {
	value bool
	set   bool
}

func (b *boolFlag) String() string {
	if b == nil {
		return "false"
	}
	return fmt.Sprintf("%t", b.value)
}

func (b *boolFlag) Set(value string) error {
	parsed, err := parseBool(value)
	if err != nil {
		return err
	}
	b.value = parsed
	b.set = true
	return nil
}

func (*boolFlag) IsBoolFlag() bool {
	return true
}

// stringFlag is a flag.Value that tracks whether it was explicitly set.
type stringFlag struct {
	value string
	set   bool
}

func (s *stringFlag) String() string {
	if s == nil {
		return ""
	}
	return s.value
}

func (s *stringFlag) Set(value string) error {
	s.value = value
	s.set = true
	return nil
}

func parseBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "1", "t", "true", "y", "yes":
		return true, nil
	case "0", "f", "false", "n", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", value)
	}
}

// runFlags holds the raw values parsed from the "run" subcommand flags.
type runFlags struct {
	readPaths    multiFlag
	writePaths   multiFlag
	rwPaths      multiFlag
	allowDomains multiFlag
	denyDomains  multiFlag
	allowNet     boolFlag
	allowExec    boolFlag
	allowPTY     boolFlag
	showProfile  boolFlag
	workDir      stringFlag
	profilePath  string
	command      []string
	usage        func()
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

	fs.Var(&f.allowNet, "allow-net", "Allow all network access (overrides domain filters)")
	fs.Var(&f.allowExec, "allow-exec", "Allow spawning child processes")
	fs.Var(&f.allowPTY, "allow-pty", "Allow pseudo-terminal allocation")
	fs.Var(&f.showProfile, "show-profile", "Print the generated sandbox profile and exit (do not run)")
	fs.Var(&f.workDir, "dir", "Working directory for the sandboxed command")
	fs.StringVar(&f.profilePath, "profile", "", "Load run options from YAML file")

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
		fmt.Fprintf(os.Stderr, "  red-keep run --profile ./profile.yaml -- echo hello\n")
	}
	f.usage = fs.Usage

	if err := fs.Parse(args); err != nil {
		return nil, 2
	}

	// Everything after "--" (or remaining args) is the command.
	f.command = fs.Args()
	return f, 0
}

// runConfigProfile defines sandbox run options that can be loaded from file
// and then overridden by CLI flags.
type runConfigProfile struct {
	ReadPaths    []string `yaml:"read_paths"`
	WritePaths   []string `yaml:"write_paths"`
	RWPaths      []string `yaml:"rw_paths"`
	AllowDomains []string `yaml:"allow_domains"`
	DenyDomains  []string `yaml:"deny_domains"`
	Command      []string `yaml:"command"`

	AllowNet    *bool   `yaml:"allow_net"`
	AllowExec   *bool   `yaml:"allow_exec"`
	AllowPTY    *bool   `yaml:"allow_pty"`
	ShowProfile *bool   `yaml:"show_profile"`
	WorkDir     *string `yaml:"work_dir"`
}

func resolveRunConfig(f *runFlags) (*runConfigProfile, error) {
	effective := &runConfigProfile{}

	if f.profilePath != "" {
		fromFile, err := loadRunConfigFile(f.profilePath)
		if err != nil {
			return nil, err
		}
		mergeRunConfigProfile(effective, fromFile)
	}

	mergeRunConfigProfile(effective, cliRunConfigOverrides(f))
	return effective, nil
}

func loadRunConfigFile(path string) (*runConfigProfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile file %q: %w", path, err)
	}

	var fileCfg runConfigProfile
	if err := yaml.Unmarshal(raw, &fileCfg); err != nil {
		return nil, fmt.Errorf("parse profile file %q: %w", path, err)
	}
	return &fileCfg, nil
}

func cliRunConfigOverrides(f *runFlags) *runConfigProfile {
	cfg := &runConfigProfile{
		ReadPaths:    append([]string{}, f.readPaths...),
		WritePaths:   append([]string{}, f.writePaths...),
		RWPaths:      append([]string{}, f.rwPaths...),
		AllowDomains: append([]string{}, f.allowDomains...),
		DenyDomains:  append([]string{}, f.denyDomains...),
		Command:      append([]string{}, f.command...),
	}

	if f.allowNet.set {
		cfg.AllowNet = boolPtr(f.allowNet.value)
	}
	if f.allowExec.set {
		cfg.AllowExec = boolPtr(f.allowExec.value)
	}
	if f.allowPTY.set {
		cfg.AllowPTY = boolPtr(f.allowPTY.value)
	}
	if f.showProfile.set {
		cfg.ShowProfile = boolPtr(f.showProfile.value)
	}
	if f.workDir.set {
		cfg.WorkDir = stringPtr(f.workDir.value)
	}

	return cfg
}

func mergeRunConfigProfile(dst *runConfigProfile, src *runConfigProfile) {
	if dst == nil || src == nil {
		return
	}

	dst.ReadPaths = append(dst.ReadPaths, src.ReadPaths...)
	dst.WritePaths = append(dst.WritePaths, src.WritePaths...)
	dst.RWPaths = append(dst.RWPaths, src.RWPaths...)
	dst.AllowDomains = append(dst.AllowDomains, src.AllowDomains...)
	dst.DenyDomains = append(dst.DenyDomains, src.DenyDomains...)

	if len(src.Command) > 0 {
		dst.Command = append([]string{}, src.Command...)
	}
	if src.AllowNet != nil {
		dst.AllowNet = boolPtr(*src.AllowNet)
	}
	if src.AllowExec != nil {
		dst.AllowExec = boolPtr(*src.AllowExec)
	}
	if src.AllowPTY != nil {
		dst.AllowPTY = boolPtr(*src.AllowPTY)
	}
	if src.ShowProfile != nil {
		dst.ShowProfile = boolPtr(*src.ShowProfile)
	}
	if src.WorkDir != nil {
		dst.WorkDir = stringPtr(*src.WorkDir)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

// buildRequest constructs a redkeep run request from resolved run options.
func buildRequest(c *runConfigProfile) redkeep.RunRequest {
	req := redkeep.RunRequest{
		ReadPaths:    append([]string{}, c.ReadPaths...),
		WritePaths:   append([]string{}, c.WritePaths...),
		RWPaths:      append([]string{}, c.RWPaths...),
		AllowDomains: append([]string{}, c.AllowDomains...),
		DenyDomains:  append([]string{}, c.DenyDomains...),
		Command:      append([]string{}, c.Command...),
	}
	if c.AllowNet != nil {
		req.AllowNet = *c.AllowNet
	}
	if c.AllowExec != nil {
		req.AllowExec = *c.AllowExec
	}
	if c.AllowPTY != nil {
		req.AllowPTY = *c.AllowPTY
	}
	if c.ShowProfile != nil {
		req.ShowProfile = *c.ShowProfile
	}
	if c.WorkDir != nil {
		req.WorkDir = *c.WorkDir
	}
	return req
}

// RunCmd executes the "run" subcommand which runs a command inside
func RunCmd(args []string) int {
	f, exitCode := parseRunFlags(args)
	if f == nil {
		return exitCode
	}

	effective, err := resolveRunConfig(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 2
	}
	if len(effective.Command) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no command specified (pass it after -- or in profile file)\n\n")
		if f.usage != nil {
			f.usage()
		}
		return 2
	}

	helperBinaryPath, _ := os.Executable()
	result, err := redkeep.Run(buildRequest(effective), redkeep.RunIO{
		Stdin:            os.Stdin,
		Stdout:           os.Stdout,
		Stderr:           os.Stderr,
		HelperBinaryPath: helperBinaryPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}
	if result.GeneratedProfile != "" {
		fmt.Print(result.GeneratedProfile)
	}
	return result.ExitCode
}
