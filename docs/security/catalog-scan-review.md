# Catalog scan review (2026-10-17)

Source revision: `5b764a277ca1dbe67d140241f11d257e02e72e0c`. With plugin-scanner 3.0.123, the original local score was 63; after these changes it is 86. These are local preflight results. Listing still requires the catalog's own completed centralized score of at least 80.

## Changes and review

Actions are pinned to immutable SHAs (the Rust action uses upstream master history with an explicit stable toolchain input where applicable), a vulnerability reporting policy and Dependabot are added, and a read-only, offline source scan runs on pushes and pull requests using the catalog's exact action SHA and score threshold. No scanner suppressions or baseline are configured.

The one HARDCODED_SECRET finding is src/bin/rbw/commands.rs:1877 at the original source revision. That code constructs PEM framing around a runtime-decoded key: the literal is a BEGIN PRIVATE KEY header, not key material. No live credential is embedded at that location. The warning remains visible; no baseline or suppression is configured.

## Reproduction

```sh
# In an isolated Python environment:
python -m pip install plugin-scanner==3.0.123
plugin-scanner scan . --format json --output /tmp/bitwarden-use-scan.json --min-score 80 --fail-on-severity none
```

## Remaining rule locations

| Rule | Severity | Location |
| --- | --- | --- |
| `HARDCODED_SECRET` | high | `src/bin/rbw/commands.rs:1877` |
