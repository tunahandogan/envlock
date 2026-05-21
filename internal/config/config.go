// Package config reads and writes the per-project .envlock/config.yaml file.
// This file tracks the envlock schema version, project name, and the list of
// authorised recipients (email + age public key pairs).
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	schemaVersion   = "1"
	envlockDirName  = ".envlock"
	configFileName  = "config.yaml"
	envlockDirPerms = 0o700
	configFilePerms = 0o644
)

// Recipient represents a team member who can decrypt the vault.
type Recipient struct {
	Email     string `yaml:"email"`
	PublicKey string `yaml:"public_key"`
}

// Config is the top-level structure of .envlock/config.yaml.
type Config struct {
	Version     string      `yaml:"version"`
	ProjectName string      `yaml:"project_name"`
	Recipients  []Recipient `yaml:"recipients"`
}

// InitConfig creates .envlock/ and writes an initial config.yaml in projectPath.
// It records email and publicKey as the first authorised recipient.
func InitConfig(projectPath, email, publicKey string) error {
	dir := filepath.Join(projectPath, envlockDirName)
	if err := os.MkdirAll(dir, envlockDirPerms); err != nil {
		return fmt.Errorf("creating %s directory: %w", envlockDirName, err)
	}

	cfg := Config{
		Version:     schemaVersion,
		ProjectName: filepath.Base(projectPath),
		Recipients: []Recipient{
			{Email: email, PublicKey: publicKey},
		},
	}
	return SaveConfig(projectPath, &cfg)
}

// LoadConfig reads and parses .envlock/config.yaml from projectPath.
func LoadConfig(projectPath string) (*Config, error) {
	path := configFilePath(projectPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	return &cfg, nil
}

// SaveConfig serialises cfg and writes it to .envlock/config.yaml in projectPath.
func SaveConfig(projectPath string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	path := configFilePath(projectPath)
	if err := os.WriteFile(path, data, configFilePerms); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}
	return nil
}

// ProjectInitialized reports whether projectPath already contains an .envlock directory.
func ProjectInitialized(projectPath string) bool {
	_, err := os.Stat(filepath.Join(projectPath, envlockDirName))
	return err == nil
}

// configFilePath returns the absolute path to the config.yaml file.
func configFilePath(projectPath string) string {
	return filepath.Join(projectPath, envlockDirName, configFileName)
}
