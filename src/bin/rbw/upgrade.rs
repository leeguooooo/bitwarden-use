//! `bitwarden-use upgrade` and the once-a-day "new version" notice, following
//! the *-use family upgrade convention (leeguooooo/plugins docs/upgrade.md).
//!
//! Nothing here talks to the agent, reads the config or touches the vault:
//! the only state is `${XDG_CACHE_HOME:-~/.cache}/bitwarden-use/
//! update-check.json`, and the only network call is the GitHub releases API.

use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;

pub const NAME: &str = "bitwarden-use";
const REPO: &str = "leeguooooo/bitwarden-use";
const PLUGIN: &str = "bitwarden-use@leeguooooo-plugins";
const INSTALL_SCRIPT: &str =
    "https://raw.githubusercontent.com/leeguooooo/bitwarden-use/main/install.sh";
const OPT_OUT_VARS: [&str; 3] =
    ["CI", "BITWARDEN_USE_NO_UPDATE_CHECK", "USE_NO_UPDATE_CHECK"];
const CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;
const NOTICE_TIMEOUT: Duration = Duration::from_secs(2);
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(15);

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// `X.Y.Z` (optionally `vX.Y.Z`, build/pre-release suffix ignored).
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim();
    let s = s.strip_prefix('v').unwrap_or(s);
    let core = s.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

/// True only when both parse and `latest` is strictly newer.
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

/// `CI`, `BITWARDEN_USE_NO_UPDATE_CHECK` or `USE_NO_UPDATE_CHECK` set to a
/// non-empty value disables the check and the notice.
pub fn checks_disabled(get: impl Fn(&str) -> Option<OsString>) -> bool {
    OPT_OUT_VARS
        .iter()
        .any(|k| get(k).is_some_and(|v| !v.is_empty()))
}

fn env_nonempty(key: &str) -> Option<OsString> {
    std::env::var_os(key).filter(|v| !v.is_empty())
}

pub fn cache_file(get: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let base = get("XDG_CACHE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            get("HOME")
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".cache"))
        })?;
    Some(base.join(NAME).join("update-check.json"))
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct CheckCache {
    pub checked_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
}

fn read_cache(path: &Path) -> Option<CheckCache> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

fn write_cache(path: &Path, cache: &CheckCache) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Per-process temp name: parallel invocations (agents often run several
    // at once) must not truncate each other's half-written temp file.
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let res = std::fs::write(&tmp, serde_json::to_vec(cache)?)
        .and_then(|()| std::fs::rename(&tmp, path));
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Fresh = checked within the last 24 h. A timestamp in the future (clock
/// moved back) counts as stale so the check cannot get stuck.
pub fn is_fresh(cache: &CheckCache, now: u64) -> bool {
    cache.checked_at <= now && now - cache.checked_at < CHECK_INTERVAL_SECS
}

pub fn notice_line(latest: &str, current: &str) -> Option<String> {
    is_newer(latest, current).then(|| {
        format!(
            "{NAME} {latest} is available (you have {current}). \
             Upgrade: {NAME} upgrade"
        )
    })
}

/// Uses the cache when fresh; otherwise calls `fetch` once and records the
/// attempt (`checked_at` is updated even when `fetch` fails, keeping the
/// previously known `latest`). Returns the notice line, if any.
pub fn check_with(
    cache_path: &Path,
    now: u64,
    current: &str,
    fetch: impl FnOnce() -> anyhow::Result<String>,
) -> Option<String> {
    let cached = read_cache(cache_path);
    let latest = match cached {
        Some(c) if is_fresh(&c, now) => c.latest,
        stale => {
            let latest =
                fetch().ok().or_else(|| stale.and_then(|c| c.latest));
            let _ = write_cache(
                cache_path,
                &CheckCache {
                    checked_at: now,
                    latest: latest.clone(),
                },
            );
            latest
        }
    };
    notice_line(&latest?, current)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The daily notice. Writes at most one line to `err` (stderr in main).
/// `skip` is true for `upgrade`; `--help`/`--version` never get here
/// because clap exits while parsing.
pub fn maybe_notify_to(
    err: &mut impl std::io::Write,
    skip: bool,
    get: impl Fn(&str) -> Option<OsString>,
    now: u64,
    fetch: impl FnOnce() -> anyhow::Result<String>,
) {
    if skip || checks_disabled(&get) {
        return;
    }
    let Some(path) = cache_file(&get) else {
        return;
    };
    if let Some(line) = check_with(&path, now, current_version(), fetch) {
        let _ = writeln!(err, "{line}");
    }
}

pub fn maybe_notify(skip: bool) {
    maybe_notify_to(
        &mut std::io::stderr(),
        skip,
        |k| std::env::var_os(k),
        now_unix(),
        || fetch_latest(NOTICE_TIMEOUT),
    );
}

/// Extracts `X.Y.Z` from a `releases/latest` response.
pub fn parse_release(v: &serde_json::Value) -> anyhow::Result<String> {
    if v["draft"].as_bool() == Some(true)
        || v["prerelease"].as_bool() == Some(true)
    {
        anyhow::bail!("latest release is a draft or prerelease");
    }
    let tag = v["tag_name"].as_str().context("release has no tag_name")?;
    let (a, b, c) = parse_version(tag)
        .with_context(|| format!("unexpected release tag {tag:?}"))?;
    Ok(format!("{a}.{b}.{c}"))
}

fn fetch_latest(timeout: Duration) -> anyhow::Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .user_agent(concat!("bitwarden-use/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let token = env_nonempty("GITHUB_TOKEN");
    let mut req = client
        .get(&url)
        .header("Accept", "application/vnd.github+json");
    if let Some(token) = &token {
        req = req.bearer_auth(token.to_string_lossy());
    }
    let mut resp = req.send()?;
    // An expired or foreign GITHUB_TOKEN must not break the check: the
    // endpoint is public, so retry once anonymously.
    if token.is_some() && resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        resp = client
            .get(&url)
            .header("Accept", "application/vnd.github+json")
            .send()?;
    }
    let resp = resp.error_for_status()?;
    let body: serde_json::Value = resp.json()?;
    parse_release(&body)
}

// ---------------------------------------------------------------- skills

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Skill {
    pub channel: &'static str,
    pub path: String,
    pub update: String,
}

#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub name: &'static str,
    pub current: String,
    pub latest: String,
    pub update_available: bool,
    pub skills: Vec<Skill>,
}

pub fn report(current: &str, latest: &str, skills: Vec<Skill>) -> Report {
    Report {
        name: NAME,
        current: current.to_string(),
        latest: latest.to_string(),
        update_available: is_newer(latest, current),
        skills,
    }
}

pub fn check_line(current: &str, latest: &str) -> String {
    if is_newer(latest, current) {
        format!("{NAME} {current} -> {latest}")
    } else {
        format!("{NAME} {current} is up to date")
    }
}

/// `installPath` of a `<name>@...` entry in `installed_plugins.json`
/// (v1 object or v2 array form), or the file itself when none is recorded.
fn plugin_install(json: &serde_json::Value, file: &Path) -> Option<String> {
    let prefix = format!("{NAME}@");
    let maps = [json.get("plugins"), Some(json)];
    for map in maps.into_iter().flatten() {
        let Some(obj) = map.as_object() else { continue };
        for (key, val) in obj {
            if !key.starts_with(&prefix) {
                continue;
            }
            let entry = val.as_array().and_then(|a| a.first()).unwrap_or(val);
            return Some(
                entry["installPath"].as_str().map_or_else(
                    || file.display().to_string(),
                    str::to_string,
                ),
            );
        }
    }
    None
}

fn git_toplevel(dir: &Path) -> Option<PathBuf> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "--show-toplevel"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let top = String::from_utf8(out.stdout).ok()?;
    let top = top.trim();
    (!top.is_empty()).then(|| PathBuf::from(top))
}

/// Every place this skill is installed, per the convention's channel table.
pub fn find_skills(home: &Path) -> Vec<Skill> {
    let mut skills = vec![];
    let plugins_file = home.join(".claude/plugins/installed_plugins.json");
    if let Some(path) = std::fs::read(&plugins_file)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .and_then(|v| plugin_install(&v, &plugins_file))
    {
        skills.push(Skill {
            channel: "claude-plugin",
            path,
            update: format!("claude plugin update {PLUGIN}"),
        });
    }
    let plugin_cache = home.join(".claude/plugins");
    let mut seen: Vec<PathBuf> = vec![];
    for dir in [".agents/skills", ".claude/skills", ".codex/skills"] {
        let link = home.join(dir).join(NAME);
        let Ok(resolved) = std::fs::canonicalize(&link) else {
            continue;
        };
        // A link into the plugin cache is the plugin channel's business.
        if std::fs::canonicalize(&plugin_cache)
            .is_ok_and(|p| resolved.starts_with(p))
        {
            continue;
        }
        if let Some(root) = git_toplevel(&resolved) {
            if !seen.contains(&root) {
                skills.push(Skill {
                    channel: "git",
                    path: root.display().to_string(),
                    update: format!(
                        "git -C {} pull --ff-only",
                        root.display()
                    ),
                });
                seen.push(root);
            }
        } else if resolved.is_dir()
            && resolved.join("SKILL.md").is_file()
            && !seen.contains(&resolved)
        {
            skills.push(Skill {
                channel: "copied",
                path: link.display().to_string(),
                update: format!("npx skills update {NAME}"),
            });
            seen.push(resolved);
        }
    }
    skills
}

fn find_on_path(
    bin: &str,
    path: Option<&std::ffi::OsStr>,
) -> Option<PathBuf> {
    std::env::split_paths(path?)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// Refreshes one skill; returns a one-line human result.
pub fn refresh_skill(
    skill: &Skill,
    path_env: Option<&std::ffi::OsStr>,
) -> String {
    match skill.channel {
        "claude-plugin" => {
            let Some(claude) = find_on_path("claude", path_env) else {
                return format!("run: {}", skill.update);
            };
            match std::process::Command::new(claude)
                .args(["plugin", "update", PLUGIN])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
            {
                Ok(s) if s.success() => "updated".to_string(),
                Ok(s) => {
                    format!("{} failed ({s}); run it by hand", skill.update)
                }
                Err(e) => {
                    format!("could not run claude ({e}): {}", skill.update)
                }
            }
        }
        "git" => match std::process::Command::new("git")
            .args(["-C", &skill.path, "pull", "--ff-only", "--quiet"])
            .stdin(std::process::Stdio::null())
            // Never block on a credential prompt (private remote, no helper).
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
        {
            Ok(o) if o.status.success() => "pulled".to_string(),
            Ok(o) => {
                let why = String::from_utf8_lossy(&o.stderr);
                let why = why
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .unwrap_or("")
                    .to_string();
                format!("not updated, git pull --ff-only failed: {why}")
            }
            Err(e) => format!("not updated, could not run git: {e}"),
        },
        _ => format!("run: {}", skill.update),
    }
}

// ---------------------------------------------------------------- install

#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// Release binary from install.sh (or unpacked by hand) in this dir.
    Installer(PathBuf),
    /// `cargo install` into ~/.cargo/bin.
    Cargo,
    /// A `target/{debug,release}` build from a checkout.
    Source(PathBuf),
}

pub fn install_route(exe: &Path, cargo_bin: Option<&Path>) -> Route {
    let dir = exe.parent().unwrap_or_else(|| Path::new("."));
    let comps: Vec<_> =
        dir.components().map(|c| c.as_os_str().to_owned()).collect();
    let in_target = comps.windows(2).any(|w| w[0] == "target")
        && comps
            .last()
            .is_some_and(|c| c == "debug" || c == "release" || c == "deps");
    if in_target {
        return Route::Source(exe.to_path_buf());
    }
    if cargo_bin.is_some_and(|c| dir == c) {
        return Route::Cargo;
    }
    Route::Installer(dir.to_path_buf())
}

fn cargo_bin() -> Option<PathBuf> {
    env_nonempty("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            env_nonempty("HOME").map(|h| PathBuf::from(h).join(".cargo"))
        })
        .map(|c| c.join("bin"))
        .and_then(|p| std::fs::canonicalize(p).ok())
}

/// Runs the repo's install.sh pinned to `v<latest>` into `dir`. The script
/// is downloaded to a temp file first so a failed download can't be mistaken
/// for a successful empty script.
fn run_installer(dir: &Path, latest: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(
            "set -eu; t=$(mktemp); trap 'rm -f \"$t\"' EXIT; \
             curl -fsSL \"$1\" -o \"$t\"; sh \"$t\"",
        )
        .arg("sh")
        .arg(INSTALL_SCRIPT)
        .env("BITWARDEN_INSTALL_DIR", dir)
        .env("BITWARDEN_VERSION", format!("v{latest}"))
        .stdin(std::process::Stdio::null())
        // install.sh reports progress on stderr and ends with a --version
        // line on stdout; keep our stdout for the summary.
        .stdout(std::process::Stdio::null())
        .status()
        .context("could not run sh")?;
    anyhow::ensure!(status.success(), "install.sh failed ({status})");
    Ok(())
}

/// `bitwarden-use upgrade [--check] [--json]`. Returns the exit code:
/// 0 on success (including "already current"), 2 when the check or the
/// download failed.
pub fn run(check: bool, json: bool) -> i32 {
    let current = current_version();
    let latest = match fetch_latest(UPGRADE_TIMEOUT) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "{NAME} upgrade: could not get the latest release: {e:#}"
            );
            return 2;
        }
    };
    if let Some(path) = cache_file(|k| std::env::var_os(k)) {
        let _ = write_cache(
            &path,
            &CheckCache {
                checked_at: now_unix(),
                latest: Some(latest.clone()),
            },
        );
    }
    let home = env_nonempty("HOME").map(PathBuf::from);
    let skills = home.as_deref().map(find_skills).unwrap_or_default();

    if json {
        let r = report(current, &latest, skills);
        match serde_json::to_string_pretty(&r) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("{NAME} upgrade: {e}");
                return 2;
            }
        }
        return 0;
    }
    if check {
        println!("{}", check_line(current, &latest));
        return 0;
    }

    let mut out = std::io::stdout().lock();
    if is_newer(&latest, current) {
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .unwrap_or_else(|_| PathBuf::from(NAME));
        match install_route(&exe, cargo_bin().as_deref()) {
            Route::Installer(dir) => {
                if let Err(e) = run_installer(&dir, &latest) {
                    eprintln!("{NAME} upgrade: {e:#}");
                    return 2;
                }
                let _ = writeln!(
                    out,
                    "{NAME} {current} -> {latest} (installed to {})",
                    dir.display()
                );
                let _ = writeln!(
                    out,
                    "note: a running {NAME}-agent keeps the old version \
                     until it next restarts"
                );
            }
            Route::Cargo => {
                let _ = writeln!(
                    out,
                    "{NAME} {current} -> {latest} available; installed \
                     with cargo, run: cargo install --locked --git \
                     https://github.com/{REPO} --tag v{latest}"
                );
            }
            Route::Source(exe) => {
                let _ = writeln!(
                    out,
                    "{NAME} {current} -> {latest} available; {} is a \
                     source build, pull the checkout and rebuild",
                    exe.display()
                );
            }
        }
    } else {
        let _ = writeln!(out, "{}", check_line(current, &latest));
    }
    let path_env = std::env::var_os("PATH");
    for skill in &skills {
        let result = refresh_skill(skill, path_env.as_deref());
        let _ = writeln!(
            out,
            "skill ({}) {}: {result}",
            skill.channel, skill.path
        );
    }
    if skills.is_empty() {
        let _ = writeln!(out, "skill: no installed copy found to refresh");
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), OsString::from(v)))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn version_comparison() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.10.0-rc.1"), Some((0, 10, 0)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("latest"), None);
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("v0.4.1", "0.4.0"));
        assert!(!is_newer("0.4.0", "0.4.0"));
        assert!(!is_newer("0.3.9", "0.4.0"));
        assert!(!is_newer("garbage", "0.4.0"));
    }

    #[test]
    fn opt_out_env_vars() {
        assert!(!checks_disabled(env(&[])));
        assert!(checks_disabled(env(&[("CI", "true")])));
        assert!(checks_disabled(env(&[(
            "BITWARDEN_USE_NO_UPDATE_CHECK",
            "1"
        )])));
        assert!(checks_disabled(env(&[("USE_NO_UPDATE_CHECK", "1")])));
        assert!(!checks_disabled(env(&[("CI", "")])));
        assert!(!checks_disabled(env(&[("RBW_NO_UPDATE_CHECK", "1")])));
    }

    #[test]
    fn cache_location() {
        assert_eq!(
            cache_file(env(&[("HOME", "/h"), ("XDG_CACHE_HOME", "/x")])),
            Some(PathBuf::from("/x/bitwarden-use/update-check.json"))
        );
        assert_eq!(
            cache_file(env(&[("HOME", "/h")])),
            Some(PathBuf::from("/h/.cache/bitwarden-use/update-check.json"))
        );
        assert_eq!(cache_file(env(&[])), None);
    }

    #[test]
    fn throttles_to_once_per_day() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bitwarden-use/update-check.json");
        let t0 = 1_700_000_000;
        let mut calls = 0;
        let line = check_with(&path, t0, "0.4.0", || {
            calls += 1;
            Ok("0.5.0".into())
        });
        assert_eq!(calls, 1);
        assert_eq!(
            line.as_deref(),
            Some(
                "bitwarden-use 0.5.0 is available (you have 0.4.0). \
                 Upgrade: bitwarden-use upgrade"
            )
        );
        assert_eq!(
            read_cache(&path),
            Some(CheckCache {
                checked_at: t0,
                latest: Some("0.5.0".into())
            })
        );
        // Within 24 h: cache only, notice still shown.
        let line =
            check_with(&path, t0 + CHECK_INTERVAL_SECS - 1, "0.4.0", || {
                panic!("fetched while cache is fresh")
            });
        assert!(line.is_some());
        // After 24 h: fetched again.
        let mut calls = 0;
        let line =
            check_with(&path, t0 + CHECK_INTERVAL_SECS, "0.5.0", || {
                calls += 1;
                Ok("0.5.0".into())
            });
        assert_eq!(calls, 1);
        assert_eq!(line, None);
    }

    #[test]
    fn failed_check_is_silent_and_still_throttled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c/update-check.json");
        let t0 = 1_700_000_000;
        assert_eq!(
            check_with(&path, t0, "0.4.0", || anyhow::bail!("offline")),
            None
        );
        assert_eq!(
            read_cache(&path),
            Some(CheckCache {
                checked_at: t0,
                latest: None
            })
        );
        assert_eq!(
            check_with(&path, t0 + 60, "0.4.0", || panic!("retried")),
            None
        );
        // A later failure keeps the last known latest.
        write_cache(
            &path,
            &CheckCache {
                checked_at: t0,
                latest: Some("0.6.0".into()),
            },
        )
        .unwrap();
        let line =
            check_with(&path, t0 + CHECK_INTERVAL_SECS, "0.4.0", || {
                anyhow::bail!("offline")
            });
        assert!(line.is_some());
        assert_eq!(
            read_cache(&path).unwrap().checked_at,
            t0 + CHECK_INTERVAL_SECS
        );
        // Clock moved backwards: treat as stale.
        assert!(!is_fresh(
            &CheckCache {
                checked_at: t0 + 10,
                latest: None
            },
            t0
        ));
    }

    #[test]
    fn notice_goes_only_to_the_given_writer_and_respects_skips() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        let mut err = vec![];
        maybe_notify_to(&mut err, false, env(&[("HOME", home)]), 1, || {
            Ok("99.0.0".into())
        });
        let text = String::from_utf8(err).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(
            text.starts_with("bitwarden-use 99.0.0 is available (you have ")
        );
        assert!(text.ends_with("). Upgrade: bitwarden-use upgrade\n"));

        for (skip, pairs) in [
            (true, vec![("HOME", home)]),
            (false, vec![("HOME", home), ("CI", "1")]),
            (false, vec![("HOME", home), ("USE_NO_UPDATE_CHECK", "1")]),
            (
                false,
                vec![("HOME", home), ("BITWARDEN_USE_NO_UPDATE_CHECK", "1")],
            ),
        ] {
            let mut err = vec![];
            maybe_notify_to(&mut err, skip, env(&pairs), 2, || {
                panic!("checked although skipped")
            });
            assert!(err.is_empty());
        }
    }

    #[test]
    fn release_parsing() {
        let v =
            serde_json::json!({"tag_name": "v0.5.0", "prerelease": false});
        assert_eq!(parse_release(&v).unwrap(), "0.5.0");
        assert!(parse_release(&serde_json::json!({"tag_name": "nightly"}))
            .is_err());
        assert!(parse_release(
            &serde_json::json!({"tag_name": "v1.0.0", "prerelease": true})
        )
        .is_err());
        assert!(parse_release(&serde_json::json!({})).is_err());
    }

    #[test]
    fn json_report_shape() {
        let r = report(
            "0.4.0",
            "0.5.0",
            vec![Skill {
                channel: "claude-plugin",
                path: "/p".into(),
                update: format!("claude plugin update {PLUGIN}"),
            }],
        );
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "name": "bitwarden-use",
                "current": "0.4.0",
                "latest": "0.5.0",
                "update_available": true,
                "skills": [{
                    "channel": "claude-plugin",
                    "path": "/p",
                    "update": "claude plugin update bitwarden-use@leeguooooo-plugins"
                }]
            })
        );
        let v =
            serde_json::to_value(report("0.5.0", "0.5.0", vec![])).unwrap();
        assert_eq!(v["update_available"], false);
        assert_eq!(v["skills"], serde_json::json!([]));
        assert_eq!(
            check_line("0.4.0", "0.5.0"),
            "bitwarden-use 0.4.0 -> 0.5.0"
        );
        assert_eq!(
            check_line("0.5.0", "0.5.0"),
            "bitwarden-use 0.5.0 is up to date"
        );
    }

    #[test]
    fn skill_channels() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        assert!(find_skills(&home).is_empty());

        // Claude Code plugin (v2 format).
        std::fs::create_dir_all(home.join(".claude/plugins")).unwrap();
        std::fs::write(
            home.join(".claude/plugins/installed_plugins.json"),
            r#"{"version":2,"plugins":{"bitwarden-use@leeguooooo-plugins":
                [{"scope":"user","installPath":"/cache/bwu"}],
                "other@x":[{}]}}"#,
        )
        .unwrap();
        // Copied folder.
        let copied = home.join(".agents/skills/bitwarden-use");
        std::fs::create_dir_all(&copied).unwrap();
        std::fs::write(copied.join("SKILL.md"), "x").unwrap();
        // Git checkout (symlinked, as a clone-based install would be).
        let repo = home.join("src/bitwarden-use");
        std::fs::create_dir_all(&repo).unwrap();
        let ok = std::process::Command::new("git")
            .args(["init", "-q"])
            .arg(&repo)
            .status()
            .is_ok_and(|s| s.success());
        std::fs::create_dir_all(home.join(".claude/skills")).unwrap();
        std::os::unix::fs::symlink(
            &repo,
            home.join(".claude/skills/bitwarden-use"),
        )
        .unwrap();
        // A link into the plugin cache is not reported twice.
        std::fs::create_dir_all(home.join(".claude/plugins/cache/b"))
            .unwrap();
        std::fs::create_dir_all(home.join(".codex/skills")).unwrap();
        std::os::unix::fs::symlink(
            home.join(".claude/plugins/cache/b"),
            home.join(".codex/skills/bitwarden-use"),
        )
        .unwrap();

        let skills = find_skills(&home);
        let channels: Vec<_> = skills.iter().map(|s| s.channel).collect();
        if ok {
            assert_eq!(channels, ["claude-plugin", "copied", "git"]);
            assert_eq!(skills[2].path, repo.display().to_string());
            // No remote: pull fails, is reported, nothing is forced.
            assert!(
                refresh_skill(&skills[2], None).starts_with("not updated")
            );
        } else {
            assert_eq!(channels, ["claude-plugin", "copied", "copied"]);
        }
        assert_eq!(skills[0].path, "/cache/bwu");
        assert_eq!(skills[1].update, "npx skills update bitwarden-use");
        // `claude` not on PATH: print the command, run nothing.
        let empty = home.join("empty-bin");
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(
            refresh_skill(&skills[0], Some(empty.as_os_str())),
            "run: claude plugin update bitwarden-use@leeguooooo-plugins"
        );
        assert_eq!(
            refresh_skill(&skills[1], None),
            "run: npx skills update bitwarden-use"
        );
    }

    #[test]
    fn install_routes() {
        let cargo = Path::new("/home/u/.cargo/bin");
        assert_eq!(
            install_route(
                Path::new("/home/u/.local/bin/bitwarden-use"),
                Some(cargo)
            ),
            Route::Installer(PathBuf::from("/home/u/.local/bin"))
        );
        assert_eq!(
            install_route(
                Path::new("/home/u/.cargo/bin/bitwarden-use"),
                Some(cargo)
            ),
            Route::Cargo
        );
        assert_eq!(
            install_route(
                Path::new("/src/bwu/target/release/bitwarden-use"),
                Some(cargo)
            ),
            Route::Source(PathBuf::from(
                "/src/bwu/target/release/bitwarden-use"
            ))
        );
    }
}
