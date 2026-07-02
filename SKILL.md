---
name: bitwarden-use
description: Command-line client for Bitwarden / self-hosted Vaultwarden vaults with an ssh-agent-style background agent and first-class FIDO2 / passkey extraction. Use when the user asks to look up a password or secret from their vault, list vault entries, sync the vault, extract a passkey (FIDO2 credential / WebAuthn private key) for headless login, or use vault-held SSH keys via the built-in SSH agent. Requires a one-time `bitwarden-use config set email <email>` and an interactive unlock (pinentry) — the agent then keeps keys in memory so subsequent commands run non-interactively.
allowed-tools: Bash(bitwarden-use:*), Bash(bwu:*)
---

# bitwarden-use

CLI for Bitwarden/Vaultwarden with a background agent (`bitwarden-use-agent`) that holds keys in
memory like `ssh-agent`, plus FIDO2/passkey extraction for headless WebAuthn logins. `bwu` is a
short alias for the same binary.

**Install / self-heal:** if `bitwarden-use` (or `bwu`) is missing, install from the GitHub Release
(no npm, no token), then retry:

```sh
curl -fsSL https://raw.githubusercontent.com/leeguooooo/bitwarden-use/main/install.sh | sh
```

Requires `pinentry` for password prompts. Existing `rbw` config/logins keep working (on-disk dirs
are named `rbw` for compatibility).

## Core commands

```sh
bitwarden-use get <name>            # password only; <name> can also be a UUID or URL
bitwarden-use get <name> --full     # + username and note
bitwarden-use get <name> --field=<field>   # a specific default/custom field
bitwarden-use get <name> --raw      # JSON
bitwarden-use ls                    # list entry names (unlocks if needed)
bitwarden-use sync                  # pull latest vault from the server
bitwarden-use unlock / lock / purge # explicit unlock / lock / logout
```

Commands log in / unlock on demand. First-time setup: `bitwarden-use config set email <email>`
(plus `base_url` for Vaultwarden). Multiple vaults: set `RBW_PROFILE=<name>`.

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
- Unlocking is interactive (pinentry). If a command blocks waiting for unlock, ask the user to run
  `bitwarden-use unlock` themselves rather than retrying.
- `bitwarden-use help` / `bitwarden-use <cmd> --help` for the full surface (add/edit/generate/…).
