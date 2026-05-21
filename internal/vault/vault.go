// Package vault defines the Vault data structure and its in-memory operations.
// Persistence (encrypt to disk / decrypt from disk) lives in storage.go.
package vault

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// Metadata records housekeeping information stored alongside the secrets.
type Metadata struct {
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by"`
	Version   int       `json:"version"`
}

// Vault holds all secrets for a project and their associated metadata.
type Vault struct {
	Secrets  map[string]string `json:"secrets"`
	Metadata Metadata          `json:"metadata"`
}

// NewVault returns an empty vault with version 1 and timestamps set to now.
func NewVault() *Vault {
	now := time.Now().UTC()
	return &Vault{
		Secrets: make(map[string]string),
		Metadata: Metadata{
			CreatedAt: now,
			UpdatedAt: now,
			Version:   1,
		},
	}
}

// Set adds or updates a secret key/value pair and bumps the vault version.
func (v *Vault) Set(key, value string) {
	v.Secrets[key] = value
	v.Metadata.UpdatedAt = time.Now().UTC()
	v.Metadata.Version++
}

// Get returns the value for key and whether it was found.
func (v *Vault) Get(key string) (string, bool) {
	val, ok := v.Secrets[key]
	return val, ok
}

// Delete removes key from the vault and bumps the version.
// It is a no-op if key does not exist.
func (v *Vault) Delete(key string) {
	delete(v.Secrets, key)
	v.Metadata.UpdatedAt = time.Now().UTC()
	v.Metadata.Version++
}

// List returns all secret keys in sorted order.
func (v *Vault) List() []string {
	keys := make([]string, 0, len(v.Secrets))
	for k := range v.Secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ToJSON serialises the vault to JSON.
func (v *Vault) ToJSON() ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encoding vault to JSON: %w", err)
	}
	return data, nil
}

// VaultFromJSON deserialises a vault from JSON produced by ToJSON.
func VaultFromJSON(data []byte) (*Vault, error) {
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decoding vault from JSON: %w", err)
	}
	if v.Secrets == nil {
		v.Secrets = make(map[string]string)
	}
	return &v, nil
}
