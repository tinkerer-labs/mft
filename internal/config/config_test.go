package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_CreatesFileWithNewIdentityOnFirstRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mft.yaml")
	os.Setenv("MFT_CONFIG", path)
	defer os.Unsetenv("MFT_CONFIG")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Identity.PrivateKey == "" {
		t.Error("expected PrivateKey to be set on first run")
	}
	if cfg.Identity.AppID == "" {
		t.Error("expected AppID to be set on first run")
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected config file to be created on first run")
	}
}

func TestLoad_ReadsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mft.yaml")
	os.Setenv("MFT_CONFIG", path)
	defer os.Unsetenv("MFT_CONFIG")

	// premier chargement — génère et sauvegarde
	first, err := Load()
	if err != nil {
		t.Fatalf("first Load() error: %v", err)
	}

	// deuxième chargement — doit retourner le même AppID
	second, err := Load()
	if err != nil {
		t.Fatalf("second Load() error: %v", err)
	}

	if second.Identity.AppID != first.Identity.AppID {
		t.Errorf("AppID changed between loads: got %q, want %q", second.Identity.AppID, first.Identity.AppID)
	}
}

func TestSave_WritesFileReadableByLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mft.yaml")
	os.Setenv("MFT_CONFIG", path)
	defer os.Unsetenv("MFT_CONFIG")

	original, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// modifie une valeur et resauvegarde
	original.Identity.AppID = "testappid"
	if err := original.Save(); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	reloaded, err := Load()
	if err != nil {
		t.Fatalf("Load() after Save() error: %v", err)
	}

	if reloaded.Identity.AppID != "testappid" {
		t.Errorf("AppID = %q, want %q", reloaded.Identity.AppID, "testappid")
	}
}
