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
`bwu login` without `--domain` retains the vault-login meaning.
If a command says the server rejected the saved login, run `bwu login --force` (keeps the offline cache); never `bwu purge`, which deletes the offline cache. Profiles use `RBW_PROFILE=<name>`.

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

## Human confirmation (0.3.0+)

- Items outside the configured `reveal_folders` (`bwu config show`) trigger a **Touch ID prompt on
  the user's Mac** for `--reveal`, `code` and `login --domain --reveal`. Tell the user a prompt is
  coming, wait, and never try to route around it (other flags, other items, reading the Keychain).
  A refused or timed-out prompt is the user's answer.
- Secrets meant for agents live in the allowed folder (for leo: `memory`). Add new ones there with
  `bwu add <name> <user> --folder memory` (password on stdin) instead of pasting them into notes.
- Every reveal is appended to `~/Library/Logs/bitwarden-use/reveal.log` (no values). Mention it if
  the user asks what was accessed.
- `fido2 get` prints metadata only; `--reveal` for the private key (always confirmed). Prefer
  `fido2 assert`.
- Unlocking may also show Touch ID (Keychain unlock). The vault locks itself when the screen locks.

## Inject, don't print (0.4.0+)

Prefer `run` whenever a secret is only needed by a command: the value goes into that process's
environment and never into your output or context.

```sh
bwu run --env GH_TOKEN='github token' -- gh api user
bwu run --env PW=bw:<uuid> --env USER_NAME='router#username' -- ./login.sh
bwu run --env KEY='openai#custom:api key' --folder memory -- python3 job.py
```

`--env` is `VAR=ITEM[#FIELD]` (ITEM: name, URI, UUID or `bw:<uuid>`; FIELD defaults to the
password; also `username`, `notes`, `totp`, `custom:<name>`). Same confirmation and audit rules as
`--reveal`. Use `get --reveal` only when the user wants to see the value or no command can take it
from the environment.

## Agent etiquette

- Treat every output as a secret: pass values via `run` (or pipes) into the consuming command, don't echo
  passwords or private keys into logs, files, or chat unless the user explicitly asks to see them.
- Default unlocking is interactive (pinentry); explicit `unlock --keychain` can use a previously
  enrolled entry. If a prompt blocks, let the user complete it rather than retrying.
- `bitwarden-use help` / `bitwarden-use <cmd> --help` for the full surface (add/edit/generate/…).

## Upgrade

When any `bitwarden-use` command prints `bitwarden-use X is available`, tell the user and offer to
run `bitwarden-use upgrade` (it updates the CLI and agent binaries through the checksummed
installer; it never touches the vault and needs no unlock). Check without changing anything:
`bitwarden-use upgrade --check` (`--json` for machine output). The user may also just say
"升级 bitwarden-use" / "upgrade bitwarden-use".

- Skill copies are only listed by default; add `--skills` to also refresh this skill (Claude Code
  plugin, its own git checkout). `--tag vX.Y.Z` pins a version.
- If it says the binary came from cargo / Homebrew / a source build, run the command it prints
  instead; it changes nothing in that case (exit 1).
- A running `bitwarden-use-agent` keeps the old version until `bitwarden-use stop-agent`; that locks
  the vault, so only suggest it and let the user decide.

If the skill came from somewhere `upgrade` can't refresh:
- Claude Code plugin: `claude plugin update bitwarden-use@leeguooooo-plugins`
- Whole family: `curl -fsSL https://raw.githubusercontent.com/leeguooooo/plugins/main/upgrade-use-family.sh | sh`
