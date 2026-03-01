package commons

import (
	"os"
	"testing"
)

func TestLoad_DefaultsToLocalConfig(t *testing.T) {
	os.Unsetenv("MFT_CONFIG")

	env := Load()

	if env.ConfigFile != "./mft.yaml" {
		t.Errorf("ConfigFile = %q, want %q", env.ConfigFile, "./mft.yaml")
	}
}

func TestLoad_ReadsFromEnvVar(t *testing.T) {
	os.Setenv("MFT_CONFIG", "/custom/path/config.yaml")
	defer os.Unsetenv("MFT_CONFIG")

	env := Load()

	if env.ConfigFile != "/custom/path/config.yaml" {
		t.Errorf("ConfigFile = %q, want %q", env.ConfigFile, "/custom/path/config.yaml")
	}
}
