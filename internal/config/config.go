// Package config reads and writes the per-project .envlock/config.yaml file.
// This file tracks the envlock schema version, project name, and the list of
// authorised recipients (email + age public key pairs).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	Email     string     `yaml:"email"`
	PublicKey string     `yaml:"public_key"`
	AddedBy   string     `yaml:"added_by,omitempty"`
	AddedOn   *time.Time `yaml:"added_on,omitempty"` // pointer so omitempty works for nil
}

// Config is the top-level structure of .envlock/config.yaml.
type Config struct {
	Version     string      `yaml:"version"`
	ProjectName string      `yaml:"project_name"`
	Recipients  []Recipient `yaml:"recipients"`
}

// InitConfig creates .envlock/ and writes an initial config.yaml in projectPath.
// It records email and publicKey as the sole authorised recipient.
func InitConfig(projectPath, email, publicKey string) error {
	dir := filepath.Join(projectPath, envlockDirName)
	if err := os.MkdirAll(dir, envlockDirPerms); err != nil {
		return fmt.Errorf("creating %s directory: %w", envlockDirName, err)
	}
	now := time.Now().UTC()
	cfg := Config{
		Version:     schemaVersion,
		ProjectName: filepath.Base(projectPath),
		Recipients: []Recipient{
			{
				Email:     email,
				PublicKey: publicKey,
				AddedBy:   email, // self-initialized
				AddedOn:   &now,
			},
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

// AddRecipient appends a new recipient to cfg. Returns an error if a recipient
// with the same email already exists.
func AddRecipient(cfg *Config, email, publicKey, addedBy string) error {
	for _, r := range cfg.Recipients {
		if r.Email == email {
			return fmt.Errorf("%s already has access. Use 'envlock recipients' to see the current list", email)
		}
	}
	now := time.Now().UTC()
	cfg.Recipients = append(cfg.Recipients, Recipient{
		Email:     email,
		PublicKey: publicKey,
		AddedBy:   addedBy,
		AddedOn:   &now,
	})
	return nil
}

// RemoveRecipient deletes the recipient with the given email from cfg.
// Returns an error if the email is not found.
func RemoveRecipient(cfg *Config, email string) error {
	for i, r := range cfg.Recipients {
		if r.Email == email {
			cfg.Recipients = append(cfg.Recipients[:i], cfg.Recipients[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%s: not found in recipients list.\nRun 'envlock recipients' to see current members", email)
}

// GetRecipientPublicKeys returns all public key strings in cfg.
// Useful for building an age.Recipient slice for encryption.
func GetRecipientPublicKeys(cfg *Config) []string {
	keys := make([]string, len(cfg.Recipients))
	for i, r := range cfg.Recipients {
		keys[i] = r.PublicKey
	}
	return keys
}

// ProjectInitialized reports whether projectPath already contains an .envlock directory.
func ProjectInitialized(projectPath string) bool {
	_, err := os.Stat(filepath.Join(projectPath, envlockDirName))
	return err == nil
}

func configFilePath(projectPath string) string {
	return filepath.Join(projectPath, envlockDirName, configFileName)
}
