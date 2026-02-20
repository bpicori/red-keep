package redkeep

import (
	"github.com/bpicori/red-keep/internal/platform"
	"github.com/bpicori/red-keep/internal/profile"
)

// Run validates and executes a sandboxed command request.
func Run(req RunRequest, ioCfg RunIO) (RunResult, error) {
	p := &profile.Profile{
		ReadPaths:    append([]string{}, req.ReadPaths...),
		WritePaths:   append([]string{}, req.WritePaths...),
		RWPaths:      append([]string{}, req.RWPaths...),
		AllowNet:     req.AllowNet,
		AllowDomains: append([]string{}, req.AllowDomains...),
		DenyDomains:  append([]string{}, req.DenyDomains...),
		AllowExec:    req.AllowExec,
		AllowPTY:     req.AllowPTY,
		WorkDir:      req.WorkDir,
		ShowProfile:  req.ShowProfile,
		Command:      append([]string{}, req.Command...),
	}

	plat, err := platform.New()
	if err != nil {
		return RunResult{}, err
	}

	if err := p.Validate(plat.SensitivePaths()); err != nil {
		return RunResult{}, err
	}

	if p.ShowProfile {
		sbpl, err := plat.GenerateProfile(p)
		if err != nil {
			return RunResult{}, err
		}
		return RunResult{
			ExitCode:         0,
			GeneratedProfile: sbpl,
		}, nil
	}

	exitCode, err := plat.Exec(p, platform.ExecOptions{
		Context:          ioCfg.Context,
		Stdin:            ioCfg.Stdin,
		Stdout:           ioCfg.Stdout,
		Stderr:           ioCfg.Stderr,
		Env:              append([]string{}, ioCfg.Env...),
		HelperBinaryPath: ioCfg.HelperBinaryPath,
	})
	if err != nil {
		return RunResult{}, err
	}

	return RunResult{ExitCode: exitCode}, nil
}
