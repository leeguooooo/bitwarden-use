# Security policy

Security fixes target the latest released version. Upgrade before checking whether a report still reproduces.

## Reporting a vulnerability

Email leeguoooo@gmail.com with the affected version, platform, reproduction steps and expected impact. Do not publish credentials, personal data or exploit details in a public issue. Prefer a minimal reproduction using synthetic data. We will assess the report and coordinate fixes and disclosure; there is no guaranteed response time or bounty program.

## Boundaries

Vault access and secret injection must be limited to trusted local processes. Masked output is not an authorization boundary; a process with access to an unlocked agent can exercise configured reveal permissions. Keep the vault, master password and backup material private, and prefer direct child-process injection over plaintext output.
