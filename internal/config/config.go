package config

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/tinkerer-labs/mft/internal/commons"
	"github.com/tinkerer-labs/mft/internal/identity"
	"go.yaml.in/yaml/v4"
)

type Config struct {
	Identity IdentityConfig `yaml:"identity"`
}

type IdentityConfig struct {
	PrivateKey string `yaml:"private_key"`
	AppID      string `yaml:"app_id"`
}

func Load() (*Config, error) {
	cl := commons.Load()

	file, err := os.Open(cl.ConfigFile)
	if os.IsNotExist(err) {
		return generateAndSave()
	}
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer file.Close()

	loader, err := yaml.NewLoader(file)
	if err != nil {
		return nil, fmt.Errorf("create yaml loader: %w", err)
	}

	var cfg Config
	if err := loader.Load(&cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Save() error {
	cl := commons.Load()

	file, err := os.OpenFile(cl.ConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open config file for writing: %w", err)
	}
	defer file.Close()

	dumper, err := yaml.NewDumper(file)
	if err != nil {
		return fmt.Errorf("create yaml dumper: %w", err)
	}
	defer dumper.Close()

	if err := dumper.Dump(c); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

func generateAndSave() (*Config, error) {
	id, err := identity.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate identity: %w", err)
	}

	cfg := &Config{
		Identity: IdentityConfig{
			PrivateKey: base64.StdEncoding.EncodeToString(id.Seed()),
			AppID:      id.AppID,
		},
	}

	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("save config: %w", err)
	}

	return cfg, nil
}
