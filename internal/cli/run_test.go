package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRunConfigFile_ParsesYAML(t *testing.T) {
	cfgPath := writeTempRunConfig(t, `
read_paths:
  - /tmp/ci-read
allow_net: true
command:
  - echo
  - from-file
`)

	cfg, err := loadRunConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("loadRunConfigFile returned error: %v", err)
	}

	if len(cfg.ReadPaths) != 1 || cfg.ReadPaths[0] != "/tmp/ci-read" {
		t.Fatalf("unexpected read paths: %#v", cfg.ReadPaths)
	}
	if cfg.AllowNet == nil || !*cfg.AllowNet {
		t.Fatalf("expected allow_net=true, got %#v", cfg.AllowNet)
	}
	if len(cfg.Command) != 2 || cfg.Command[0] != "echo" || cfg.Command[1] != "from-file" {
		t.Fatalf("unexpected command: %#v", cfg.Command)
	}
}

func TestResolveRunConfig_MergesFileAndCLIOverrides(t *testing.T) {
	cfgPath := writeTempRunConfig(t, `
allow_exec: true
command:
  - echo
  - from-file
`)

	f := &runFlags{
		profilePath: cfgPath,
	}
	f.allowExec.value = false
	f.allowExec.set = true
	f.command = []string{"echo", "from-cli"}

	cfg, err := resolveRunConfig(f)
	if err != nil {
		t.Fatalf("resolveRunConfig returned error: %v", err)
	}

	if cfg.AllowExec == nil || *cfg.AllowExec {
		t.Fatalf("expected allow_exec=false after CLI override, got %#v", cfg.AllowExec)
	}
	if len(cfg.Command) != 2 || cfg.Command[1] != "from-cli" {
		t.Fatalf("expected CLI command override, got %#v", cfg.Command)
	}
}

func TestLoadRunConfigFile_InvalidYAML(t *testing.T) {
	cfgPath := writeTempRunConfig(t, `: not-valid`)
	_, err := loadRunConfigFile(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid yaml")
	}
}

func writeTempRunConfig(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "run-config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}
