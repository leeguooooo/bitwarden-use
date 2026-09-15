# Remote approval from the phone (design, not implemented)

Status: proposal, 2026-09-15. Touch ID only works when the user sits at the Mac. When they drive
agents remotely from a phone, the screen is locked: the vault locks itself, and both the Touch ID
dialog and pinentry appear on a screen nobody can see. This is the design for approving from the
phone instead. Nothing here is built yet.

## Shape: CIBA

It follows OpenID CIBA (Client-Initiated Backchannel Authentication), the pattern Auth0/Okta ship
as "asynchronous authorization" for AI agents: the requester starts a request, the user is asked
out of band, the requester waits for the answer. Keeping that shape means a later switch to a
standard service (or Bitwarden's Agent Access SDK, alpha in 2026) changes the transport, not the
callers.

```
bitwarden-use (Mac)                relay (Cloudflare Worker, untrusted)          iPhone app
  build request R  ── POST /req ──►  store R (≤120 s)  ── APNs push ──►  show R's text
                                                                          Face ID → sign(R)
  poll/long-poll  ◄── signature ──  store signature  ◄── POST /resp ──  (Secure Enclave key)
  verify sig with pinned public key, check R matches, then unlock / reveal; audit auth="phone"
```

## Request

`R` is canonical JSON: `{cmd, item, id, field, folder, caller, host, nonce, expires}` — exactly
what the audit log records, plus a random nonce and an expiry (120 s). The phone displays these
fields as text and signs the exact bytes it displayed ("what you see is what you sign"). The Mac
rebuilds `R` from the real request and compares; a misleading request text from a compromised
agent produces a signature over the wrong bytes and is rejected.

## Keys and trust

- The phone app creates a P-256 key in the Secure Enclave with `.biometryCurrentSet` access
  control: non-exportable, not synced to iCloud, unusable without Face ID, invalidated when
  biometrics change. (A passkey would sync to the Mac through iCloud Keychain — avoided on
  purpose.)
- Pairing, once: the Mac shows a QR code with a pairing nonce; the phone scans it and returns its
  public key signed over that nonce. The Mac pins the public key in the config
  (`phone_approval_keys`). Removing it revokes the phone.
- The relay only moves bytes. It cannot approve (no private key) and cannot alter `R` (the Mac
  checks it). A compromised relay can only delay or drop requests — the request then times out,
  which is a denial.
- APNs credentials (.p8 key from the Apple Developer account) live in the Worker as a secret, not
  on the Mac, so a local agent cannot send pushes pretending to be the relay.

## Policy on the Mac

- `confirm_backend = auto`: start Touch ID and the phone request at the same time; the first
  approval wins, a denial on either side denies. With the screen locked only the phone can answer.
- Keychain unlock uses the same path, so a remote session can unlock the vault after approval
  (the login keychain stays readable while the user is logged in, even with the screen locked).
- Timeout 120 s = denial. Every decision is logged with `auth: "touchid" | "phone" | "denied"`.

## Out of scope / limits

- A root-level compromise of the Mac defeats this, as it defeats Touch ID today.
- After a reboot, before anyone logs in, nothing is unlockable (same as now).
- Push delivery depends on APNs and on the phone having a network path to the relay (in China,
  through the VPN).

## Rough effort

iOS app (SwiftUI, notification action, Secure Enclave signing, QR pairing) ≈ 1 day; relay Worker
(request store + APNs) ≈ half a day; bitwarden-use confirm backend + pairing command ≈ half a day.
