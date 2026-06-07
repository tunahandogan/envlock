# envlock

Encrypted `.env` management for teams — commit secrets safely using [age](https://age-encryption.org/) encryption.

```
envlock add DATABASE_URL=postgres://prod.example.com/mydb
# ✓ Added DATABASE_URL (encrypted for 3 recipient(s))
```

Secrets live in `.envlock/vault.age` — a single age-encrypted file you commit to git. Each team member holds their own private key; the vault is encrypted for everyone simultaneously. No shared passwords, no plaintext `.env` files in the repository.

---

## Installation

```sh
go install github.com/tunahandogan/envlock/cmd/envlock@latest
```

Or build from source:

```sh
git clone https://github.com/tunahandogan/envlock
cd envlock
go build -o envlock ./cmd/envlock
```

---

## Quick start

### 1 — Initialize your project

```sh
cd your-project
envlock init --email you@example.com
```

This generates an age keypair, saves your private key to `~/.envlock/keys/you@example.com.key`, and creates `.envlock/config.yaml`. It also adds `.env` and `.env.*` to your project's `.gitignore`.

### 2 — Add secrets

```sh
envlock add DATABASE_URL=postgres://localhost/mydb
envlock add STRIPE_SECRET_KEY=sk_live_...
envlock add API_TOKEN=supersecret
```

### 3 — Commit the vault

```sh
git add .envlock/
git commit -m "feat: add envlock"
```

Your `.env` file is never committed — only the encrypted vault.

### 4 — Use secrets locally

Write to a `.env` file:

```sh
envlock pull          # writes .env
envlock pull --output .env.local
```

Or inject directly into a process (no file written):

```sh
envlock run -- npm start
envlock run -- pytest -v
envlock run -- go run .
```

---

## Team workflow

### Adding a teammate

Alice runs `envlock init` and shares her public key:

```sh
# Alice
envlock init --email alice@example.com
envlock pubkey
# age1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
```

Bob grants her access:

```sh
# Bob
envlock grant alice@example.com --key age1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
git add .envlock/ && git commit -m "grant envlock access to alice"
```

Alice pulls the repository and can now decrypt the vault with her private key.

### Removing a teammate

```sh
envlock revoke alice@example.com
git add .envlock/ && git commit -m "revoke envlock access from alice"
```

The vault is immediately re-encrypted without Alice's key. Past git history still contains old encrypted versions — if this is a security incident, rotate your secrets:

```sh
envlock rotate --all
```

---

## Command reference

| Command | Description |
|---|---|
| `envlock init` | Generate a keypair and initialise the project |
| `envlock add KEY=VALUE` | Add or update a secret |
| `envlock get KEY` | Print a secret value (`--copy` to clipboard) |
| `envlock list` | List secret keys (`--values` to show values, `--json` for scripts) |
| `envlock remove KEY` | Delete a secret |
| `envlock rotate KEY` | Replace a secret value with secure hidden input |
| `envlock rotate --all` | Interactively rotate every secret (post-incident workflow) |
| `envlock pull` | Write all secrets to a `.env` file |
| `envlock push` | Sync a `.env` file into the vault |
| `envlock run -- CMD` | Run a command with secrets injected as environment variables |
| `envlock export` | Export secrets in shell / docker / json / dotenv / github-actions format |
| `envlock recipients` | List everyone with vault access |
| `envlock grant EMAIL --key AGE1...` | Grant a teammate vault access |
| `envlock revoke EMAIL` | Remove a teammate's vault access |
| `envlock pubkey` | Print your age public key |

---

## Exporting secrets

```sh
# Load into current shell
eval $(envlock export --format shell)

# Pass to Docker
docker run $(envlock export --format docker) myimage

# Pipe to jq
envlock export --format json | jq '.DATABASE_URL'

# Write .env for another environment
envlock export --format dotenv > .env.production

# GitHub Actions — append to $GITHUB_ENV
envlock export --format github-actions >> $GITHUB_ENV
```

---

## Security model

- **Age encryption** — each secret is encrypted using [filippo.io/age](https://pkg.go.dev/filippo.io/age) with X25519 keys.
- **Multi-recipient** — the vault is encrypted once for all recipients simultaneously; no secret is encrypted multiple times.
- **Private keys never leave the machine** — they are stored at `~/.envlock/keys/<email>.key` (mode `0600`) and are never included in the repository.
- **Atomic writes** — vault saves go through a `.tmp` file and an `os.Rename`, so a crash during write cannot corrupt the vault.
- **No plaintext on disk** — `envlock run` injects secrets directly into the subprocess environment without writing a `.env` file.
- **Git history caveat** — revoking a recipient re-encrypts the current vault but does not rewrite git history. Old encrypted snapshots remain accessible to anyone who held a valid key at that time. Rotate secrets after any security incident.

---

## How it works

```
.envlock/
  config.yaml   # project name + recipients (public keys) — commit this
  vault.age     # age-encrypted JSON blob of all secrets — commit this

~/.envlock/
  keys/
    you@example.com.key   # your private key — never leave this machine
```

`vault.age` is PEM-armored age ciphertext, which means it produces readable diffs in `git log` and `git diff` (no binary noise).

---

## Contributing

Bug reports and pull requests are welcome. Run the test suite with:

```sh
go test ./...
```
