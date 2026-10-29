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

### Profile sync, native items and attachments (0.12+)

Personal facts and form workflows belong to profile-use; infrastructure notes belong
to memory-use. Secrets have one authoritative vault entry; those workflows may reference
its UUID/field. bitwarden-use owns generic vault operations and authorization, not
personal schemas, form formatting or technical runbooks.

Use profile-use's `python3 scripts/profile_use.py sync --profile personal --dry-run`,
then `--yes` within the user's authorized sync scope. The old `bwu profile sync FILE`
delegates to the installed profile-use skill. Requires Python 3.9+. It preserves the
whole JSON in secure notes, creates native identity/card entries, uploads original
document attachments, and verifies text plus every downloaded file. Re-running
updates only this helper's managed entries and avoids duplicate attachment uploads.
It leaves local sources and earlier attachment versions intact. No schedule is installed.

`bwu item put - --folder profile-use --dry-run` accepts native Bitwarden-shaped JSON
on stdin: `name`, numeric `type` (2 note, 3 card, 4 identity, 5 SSH key), `notes`, the matching
`card`/`identity`/`sshKey` payload, and optional `fields`. Fields use camelCase. SSH keys require `privateKey`, `publicKey` and `keyFingerprint`; read private files directly into the stdin producer, never print or put them in arguments. Use `--id UUID`
to replace an existing item's payload/notes; omitted custom fields are preserved. Never put real values in command
arguments; pipe from the private source. Type changes require `--convert`: a new
UUID is created, the original is retained, and entries with attachments are refused.
Verify the replacement before removing an original, within the authorized migration scope. Duplicate names and mixed payloads are refused.

```sh
bwu attachment list ITEM_UUID                       # names masked
bwu attachment list ITEM_UUID --reveal
bwu attachment upload ITEM_UUID /private/file --dry-run
bwu attachment upload ITEM_UUID /private/file --yes
bwu attachment download ITEM_UUID ATTACHMENT_ID --output - | consumer
```

Downloads are audited reveals; let Touch ID/master-password checks complete.
Files are encrypted locally before upload. Downloads authenticate before writing,
refuse overwrite, and use 0600 for output files. No shared-item writes or legacy
keyless downloads; 128 MiB per file. If an upload fails after creating metadata,
inspect saved state before retrying. Binary crypto needs the upgraded agent; do
not work around it by extracting vault keys or changing reveal policy.

Without `--reveal`, `get` outputs the literal `[redacted]` with exit code 0 and a hint on stderr when a value is masked; use `--reveal` or `bwu run --env VAR=ITEM -- <command>` to consume the real value.

```sh
bwu get <name> --json                  # masked structured fields; --raw also works
bwu get <name> --field password --reveal # pass directly to the consumer, never log
bwu get <name> --field 'custom:Recovery codes' --reveal # exact custom name
bwu get <name> --codes --reveal          # standalone recovery-code lines from notes
bwu login --domain example.com         # masked unique domain match
bwu login --domain example.com --list  # all matches, masked, most recently used first
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

## Organizing folders

```sh
bwu folder list --json                 # IDs and names, including empty folders
bwu folder create 'Work' --dry-run
bwu folder create 'Work' --yes
bwu ls --fields id,name,folder
bwu move UUID1 UUID2 --to 'Work' --dry-run
bwu move UUID1 UUID2 --to 'Work' --yes
bwu move UUID1 --clear --dry-run
```

Move requires exact entry UUIDs. The destination is an existing exact folder
name or UUID; duplicate names require a UUID. Creating an existing unique name
or moving to the current folder makes no change. Preview first. Moves touch only
folder membership and preserve secrets, passkeys, attachments and sharing settings;
no secret fields are decrypted. Moving into `reveal_folders` affects reveal policy
and is called out in the preview. Batch moves are sequential, stop on the first
failure, and report the completed count and sync result. A failed request may
already be accepted: inspect synced state before retrying. Do not export the
vault's plaintext to classify it. Keep classification proposals outside public
repositories, and leave uncertain assignments for review.

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
- Moving the user's passwords over from Apple Passwords, Google or 1Password: they export a CSV,
  then `bwu import FILE --dry-run`, show them the list, and `bwu import FILE --yes` once they agree.
  Remind them to delete the CSV afterwards; it holds every password in plain text.
- Every reveal is appended to `~/Library/Logs/bitwarden-use/reveal.log` (no values). Mention it if
  the user asks what was accessed.
- `fido2 get` prints metadata only; `--reveal` for the private key (always confirmed). Prefer
  `fido2 assert`.
- Unlocking may also show Touch ID (Keychain unlock). The vault locks itself when the screen locks.
- With `require_touch_id` set to `false` (`bwu config show`; leo's Mac, for unattended runs) none of
  this prompts: unlock and reveals go through, still audited as `trusted-device`. Don't turn it
  on or off yourself; it is the user's decision.

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

## Logging in to a website (0.7.0+)

With chrome-use 1.5.155+, prefer `chrome-use auth login --bwu` on the login page: it picks the account and
fills it through `run`. Doing it by hand:

1. `bwu login --domain <url> --list` — candidates with `uses` / `last_used`. One candidate: use
   it. Several: select the UUID identified by the user's request; otherwise ask.
   Do not silently pick the most recently used account.
2. `bwu login --domain <url> --name <uuid>` — masked item with `autotype`: the site's login
   steps (`username`, `password`, `totp`, `tab`, `enter`, `delay`, `custom:<name>`) from the
   item's `_autotype` field, or null for the plain username → password → submit.
3. `bwu run --env U=bw:<uuid>#username --env P=bw:<uuid>#password -- chrome-use …` — one
   Touch ID prompt for the item. Fetch `#totp` in a separate `run` when the code field appears,
   so the code is fresh.

With a chrome-use build whose `auth --help` lists `--totp`, default login waits
for a code field before a second `bwu run` fetches TOTP from the same selected
item. Each phase is audited and may require authorization. On an existing
challenge use `chrome-use auth login --bwu --totp --item <uuid>`: only TOTP is
read, and username/password and `_autotype` are skipped. It cannot be combined
with `--passkey` or `--no-submit`. A rejected code is not retried automatically;
inspect the page before another attempt. Pending human verification must not be
reported as signed in or navigated away from.

The login's authenticator field must contain its TOTP setup key or `otpauth://`
URI. A stored password or a current six-digit code is insufficient. Have the
user migrate the setup key through the vault UI; never request it in chat or
put a real setup key in command arguments. Keep the original authenticator
until the new setup has been checked. SMS/email codes and push approvals have
separate sources; do not submit a vault TOTP for those challenges. Custom
`_autotype` sequences still fetch all values before starting; use `--totp` on
the code page if a long sequence used up the code's lifetime.

Passkeys: `login --domain` reports `passkeys` (a count). With chrome-use 1.5.157+, `auth login --bwu`
answers a passkey / security-key second factor with it, and `auth login --bwu --passkey` signs in
with the passkey alone. By hand: `bwu run --env PK=bw:<uuid>#passkeys -- <tool>` (JSON for Chrome's
`WebAuthn.addCredential`; it contains the private key, so it goes only into the consuming process).

`get --clipboard` (needs `--reveal`) copies a value that is hidden from clipboard history and
cleared after `clipboard_clear_after` seconds (default 30). Prefer `run`; copy only when the user
wants to paste it themselves.

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

Installed as the Claude Code plugin, the CLI follows the plugin on its own: at session start a hook
upgrades an older CLI to the plugin's version and reports it in one line. If that line says the
upgrade failed, tell the user and show the command it prints.
