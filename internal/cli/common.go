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
	env        string // vault environment ("" = default)
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
			// A key file exists for this recipient but cannot be used
			// (wrong passphrase, corrupt file). Surface the real error
			// instead of a misleading "no local key found".
			return nil, err
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
	if err := vault.ValidateEnvName(envFlag); err != nil {
		return nil, err
	}
	v, err := vault.LoadVaultEnv(cwd, envFlag, identity)
	if err != nil {
		return nil, err
	}
	recipients, err := parseRecipients(cfg)
	if err != nil {
		return nil, err
	}
	return &vaultCtx{dir: cwd, env: envFlag, vault: v, recipients: recipients}, nil
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

// reencryptAllVaults decrypts every vault file (all environments) with
// identity and re-encrypts each one for recipients. Used by grant and revoke,
// which change the recipient list. Returns the total number of secrets and
// the number of vault files processed.
func reencryptAllVaults(dir string, identity age.Identity, recipients []age.Recipient) (secrets, vaults int, err error) {
	envs, err := vault.ListEnvs(dir)
	if err != nil {
		return 0, 0, err
	}
	if len(envs) == 0 {
		// No vault written yet — nothing to re-encrypt.
		return 0, 0, nil
	}
	for _, e := range envs {
		v, err := vault.LoadVaultEnv(dir, e, identity)
		if err != nil {
			return 0, 0, err
		}
		if err := vault.SaveVaultEnv(dir, e, v, recipients); err != nil {
			return 0, 0, fmt.Errorf("re-encrypting vault %s: %w", vault.VaultFileName(e), err)
		}
		secrets += len(v.List())
		vaults++
	}
	return secrets, vaults, nil
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
