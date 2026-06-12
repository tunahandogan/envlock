// storage.go handles reading and writing the encrypted vault file on disk.
// Vault files live at <project>/.envlock/vault.age (default environment) or
// <project>/.envlock/vault.<env>.age (named environments) and are PEM-armored
// age ciphertext containing a JSON-encoded Vault struct.
package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"filippo.io/age"

	"github.com/tunahandogan/envlock/internal/crypto"
)

const (
	envlockDirName  = ".envlock"
	vaultFilePrefix = "vault"
	vaultFileExt    = ".age"
	vaultFilePerms  = 0o644
)

// envNameRE restricts environment names to safe filename characters.
var envNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// ValidateEnvName returns an error if env is not a usable environment name.
// The empty string is valid and refers to the default environment.
func ValidateEnvName(env string) error {
	if env == "" {
		return nil
	}
	if !envNameRE.MatchString(env) {
		return fmt.Errorf("invalid environment name %q: use letters, digits, '-' and '_' only", env)
	}
	return nil
}

// VaultFileName returns the vault file name for env:
// "vault.age" for the default environment, "vault.<env>.age" otherwise.
func VaultFileName(env string) string {
	if env == "" {
		return vaultFilePrefix + vaultFileExt
	}
	return vaultFilePrefix + "." + env + vaultFileExt
}

// SaveVault encrypts v for all recipients and writes the default-environment
// vault. Shorthand for SaveVaultEnv with an empty environment.
func SaveVault(projectPath string, v *Vault, recipients []age.Recipient) error {
	return SaveVaultEnv(projectPath, "", v, recipients)
}

// SaveVaultEnv encrypts v for all recipients and writes it atomically to the
// vault file for env. An intermediate .tmp file is used so that a crash
// during write cannot leave a partial vault on disk.
func SaveVaultEnv(projectPath, env string, v *Vault, recipients []age.Recipient) error {
	if err := ValidateEnvName(env); err != nil {
		return err
	}
	jsonData, err := v.ToJSON()
	if err != nil {
		return err
	}
	defer zeroBytes(jsonData)

	ciphertext, err := crypto.Encrypt(jsonData, recipients)
	if err != nil {
		return fmt.Errorf("encrypting vault: %w", err)
	}

	dir := filepath.Join(projectPath, envlockDirName)
	name := VaultFileName(env)
	tmpPath := filepath.Join(dir, name+".tmp")
	vaultPath := filepath.Join(dir, name)

	if err := os.WriteFile(tmpPath, ciphertext, vaultFilePerms); err != nil {
		return fmt.Errorf("writing vault to disk: %w", err)
	}
	if err := os.Rename(tmpPath, vaultPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("committing vault file: %w", err)
	}
	return nil
}

// LoadVault reads and decrypts the default-environment vault.
// Shorthand for LoadVaultEnv with an empty environment.
func LoadVault(projectPath string, identity age.Identity) (*Vault, error) {
	return LoadVaultEnv(projectPath, "", identity)
}

// LoadVaultEnv reads and decrypts the vault file for env using identity.
// If the vault file does not yet exist (first use), an empty vault is returned.
func LoadVaultEnv(projectPath, env string, identity age.Identity) (*Vault, error) {
	if err := ValidateEnvName(env); err != nil {
		return nil, err
	}
	vaultPath := filepath.Join(projectPath, envlockDirName, VaultFileName(env))

	ciphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewVault(), nil
		}
		return nil, fmt.Errorf("reading vault file: %w", err)
	}

	jsonData, err := crypto.Decrypt(ciphertext, identity)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(jsonData)

	return VaultFromJSON(jsonData)
}

// ListEnvs returns the environment names of all vault files present in
// <projectPath>/.envlock, in directory order. The default environment is
// reported as the empty string. Returns an empty slice if no vault exists yet.
func ListEnvs(projectPath string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(projectPath, envlockDirName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s directory: %w", envlockDirName, err)
	}

	var envs []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, vaultFilePrefix) || !strings.HasSuffix(name, vaultFileExt) {
			continue
		}
		middle := strings.TrimSuffix(strings.TrimPrefix(name, vaultFilePrefix), vaultFileExt)
		switch {
		case middle == "":
			envs = append(envs, "") // vault.age — default environment
		case strings.HasPrefix(middle, "."):
			env := middle[1:]
			if ValidateEnvName(env) == nil {
				envs = append(envs, env) // vault.<env>.age
			}
		}
	}
	return envs, nil
}

// zeroBytes overwrites b with zeros to minimise the time sensitive data
// lingers in memory. Should be called via defer immediately after allocation.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
