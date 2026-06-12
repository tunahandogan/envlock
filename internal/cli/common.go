// common.go contains shared helpers used by every vault command.
// All vault commands follow the same preamble:
//
//	requireInitialized → loadConfig → getCurrentIdentity → loadVault → parseRecipients
package cli

import (
	"fmt"
	"os"

	"filippo.io/age"

	"github.com/tunahandogan/envlock/internal/config"
	icrypto "github.com/tunahandogan/envlock/internal/crypto"
	"github.com/tunahandogan/envlock/internal/keys"
	"github.com/tunahandogan/envlock/internal/vault"
)

// vaultCtx bundles everything a command needs to read or mutate the vault.
type vaultCtx struct {
	dir        string
	vault      *vault.Vault
	recipients []age.Recipient
}

// requireInitialized returns the working directory, or an actionable error if
// the project has not been initialised yet.
func requireInitialized() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}
	if !config.ProjectInitialized(cwd) {
		return "", fmt.Errorf("not initialized. Run 'envlock init' to get started")
	}
	return cwd, nil
}

// getCurrentIdentity iterates the project's recipients and returns the first
// private key that exists on this machine.
func getCurrentIdentity(cfg *config.Config) (age.Identity, error) {
	for _, r := range cfg.Recipients {
		ok, err := keys.KeyExists(r.Email)
		if err != nil || !ok {
			continue
		}
		identity, err := keys.LoadPrivateKey(r.Email)
		if err != nil {
			continue
		}
		return identity, nil
	}
	return nil, fmt.Errorf(
		"no local key found for any project recipient.\n" +
			"Ensure your key is in ~/.envlock/keys/ or run 'envlock init' to generate one",
	)
}

// loadVaultCtx is the standard preamble for every vault command.
// It verifies initialization, loads config, resolves the local identity,
// decrypts the vault, and builds the recipient list for re-encryption.
func loadVaultCtx() (*vaultCtx, error) {
	cwd, err := requireInitialized()
	if err != nil {
		return nil, err
	}
	cfg, err := config.LoadConfig(cwd)
	if err != nil {
		return nil, fmt.Errorf("loading project config: %w", err)
	}
	identity, err := getCurrentIdentity(cfg)
	if err != nil {
		return nil, err
	}
	v, err := vault.LoadVault(cwd, identity)
	if err != nil {
		return nil, err
	}
	recipients, err := parseRecipients(cfg)
	if err != nil {
		return nil, err
	}
	return &vaultCtx{dir: cwd, vault: v, recipients: recipients}, nil
}

// parseRecipients converts the config recipient list into age.Recipient values
// suitable for passing to vault.SaveVault.
func parseRecipients(cfg *config.Config) ([]age.Recipient, error) {
	rs := make([]age.Recipient, 0, len(cfg.Recipients))
	for _, r := range cfg.Recipients {
		rec, err := icrypto.ParseRecipient(r.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("parsing public key for %s: %w", r.Email, err)
		}
		rs = append(rs, rec)
	}
	return rs, nil
}

// GetAllRecipients is an exported wrapper around parseRecipients for commands
// that manipulate the recipient list directly (grant, revoke).
func GetAllRecipients(cfg *config.Config) ([]age.Recipient, error) {
	return parseRecipients(cfg)
}

// currentUserEmail returns the email of the first project recipient whose
// private key exists on this machine, or an empty string if none is found.
func currentUserEmail(cfg *config.Config) string {
	for _, r := range cfg.Recipients {
		ok, _ := keys.KeyExists(r.Email)
		if ok {
			return r.Email
		}
	}
	return ""
}
