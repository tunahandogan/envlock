// storage.go handles reading and writing the encrypted vault file on disk.
// The vault file lives at <project>/.envlock/vault.age and is PEM-armored
// age ciphertext containing a JSON-encoded Vault struct.
package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"

	"github.com/tunahandogan/envlock/internal/crypto"
)

const (
	envlockDirName   = ".envlock"
	vaultFileName    = "vault.age"
	vaultTmpFileName = "vault.age.tmp"
	vaultFilePerms   = 0o644
)

// SaveVault encrypts v for all recipients and writes it atomically to
// <projectPath>/.envlock/vault.age. An intermediate .tmp file is used so that
// a crash during write cannot leave a partial vault on disk.
func SaveVault(projectPath string, v *Vault, recipients []age.Recipient) error {
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
	tmpPath := filepath.Join(dir, vaultTmpFileName)
	vaultPath := filepath.Join(dir, vaultFileName)

	if err := os.WriteFile(tmpPath, ciphertext, vaultFilePerms); err != nil {
		return fmt.Errorf("writing vault to disk: %w", err)
	}
	if err := os.Rename(tmpPath, vaultPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("committing vault file: %w", err)
	}
	return nil
}

// LoadVault reads and decrypts <projectPath>/.envlock/vault.age using identity.
// If the vault file does not yet exist (first use), an empty vault is returned.
func LoadVault(projectPath string, identity age.Identity) (*Vault, error) {
	vaultPath := filepath.Join(projectPath, envlockDirName, vaultFileName)

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

// zeroBytes overwrites b with zeros to minimise the time sensitive data
// lingers in memory. Should be called via defer immediately after allocation.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
