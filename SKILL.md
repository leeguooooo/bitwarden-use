---
name: bitwarden-use
description: Command-line client for Bitwarden / self-hosted Vaultwarden vaults with an ssh-agent-style background agent and first-class FIDO2 / passkey extraction. Use when the user asks to look up a password or secret from their vault, list vault entries, sync the vault, extract a passkey (FIDO2 credential / WebAuthn private key) for headless login, or use vault-held SSH keys via the built-in SSH agent. Supports safe field updates, masked JSON reads, domain selection, and explicit macOS login Keychain unlock after one-time enrollment.
allowed-tools: Bash(bitwarden-use:*), Bash(bwu:*)
---

# bitwarden-use

CLI for Bitwarden/Vaultwarden with a background agent (`bitwarden-use-agent`) that holds keys in
memory like `ssh-agent`, plus FIDO2/passkey extraction for headless WebAuthn logins. `bwu` is a
short alias for the same binary.

**Install / self-heal:** if `bitwarden-use` (or `bwu`) is missing or older than 0.2.0, install from the GitHub Release
(no npm, no token), then retry:

```sh
curl -fsSL https://raw.githubusercontent.com/leeguooooo/bitwarden-use/main/install.sh | sh
```

Requires `pinentry` for password prompts. Existing `rbw` config/logins keep working (on-disk dirs
are named `rbw` for compatibility).

## Core commands

```sh
bwu get <name> --json                  # masked structured fields; --raw also works
bwu get <name> --field password --reveal # pass directly to the consumer, never log
bwu get <name> --field 'custom:Recovery codes' --reveal # exact custom name
bwu get <name> --codes --reveal          # standalone recovery-code lines from notes
bwu login --domain example.com         # masked unique domain match
bwu login --domain example.com --name <item-or-uuid> --user <username> --reveal
bwu set <name> --uri https://example.com --match host --dry-run
bwu set <name> --uri https://example.com --match host --yes
bwu set <name> --uri-add https://login.example.com --match host --yes
bwu set <name> --uri-remove https://login.example.com --yes
bwu set <name> --totp <seed-or-otpauth-uri> --yes
bwu set <name> --field 'NAME=VALUE' --yes
bwu set <name> --notes '' --allow-empty --yes
bwu ls
bwu sync
```

`set` changes only named fields. `--uri` replaces the list; additions/removals retain other URIs.
Modes: base, host, exact, regex, starts-with, never. Empty values or removal of the last URI require
`--allow-empty`. Writes preview masked field changes on stderr; noninteractive calls require
`--yes`. Prefer `--dry-run` before applying a reviewed update. If the server changed a selected
field, sync and review again instead of retrying blindly. A write accepted followed by a failed
sync must not be repeated before checking the saved state.

`get` and `login --domain` mask values by default, including JSON. Use `--reveal` only to pass
secrets directly to their intended consumer. Multiple domain matches produce no credentials,
even with `--reveal`: use the returned UUID with `--name`, or exact name/user filters. Never
choose an arbitrary candidate or fall back to a similarly named account. `--field` custom names
are exact; prefix `custom:` for names overlapping built-ins. `--codes` recognizes complete
code-shaped lines only and does not validate whether a recovery code is usable.

First-time setup: `bwu config set email <email>` (plus `base_url` for Vaultwarden), then `bwu login`.
`bwu login` without `--domain` retains the vault-login meaning. Profiles use `RBW_PROFILE=<name>`.

## macOS Keychain unlock

```sh
bwu unlock --keychain-store  # user opts in once; pinentry password verified before saving
bwu unlock --keychain        # explicitly use the enrolled login-keychain entry
```

Storage is scoped to server, email and profile. macOS may require a first-access approval; this
is not bypassed. Missing/denied/stale keychain entries fail explicitly. Ask the user to enroll or
re-enroll; never scrape unrelated keychain records or save a master password without their choice.
Item-level master-password reprompts still require interactive verification.

## FIDO2 / passkeys

```sh
bitwarden-use fido2 list            # passkeys: entry name, rpId, credentialId
bitwarden-use fido2 get <name>      # decrypted private key (base64url + PKCS#8 PEM)
```

## SSH agent

```sh
bitwarden-use unlock
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/rbw/ssh-agent-socket"   # rbw-<profile> if RBW_PROFILE set
```

## Agent etiquette

- Treat every output as a secret: pass values via pipes/env into the consuming command, don't echo
  passwords or private keys into logs, files, or chat unless the user explicitly asks to see them.
- Default unlocking is interactive (pinentry); explicit `unlock --keychain` can use a previously
  enrolled entry. If a prompt blocks, let the user complete it rather than retrying.
- `bitwarden-use help` / `bitwarden-use <cmd> --help` for the full surface (add/edit/generate/…).
