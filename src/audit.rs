//! Append-only record of every plaintext reveal: when, what, which field,
//! who asked, and how it was authorized. Never the value itself.
//!
//! macOS: `~/Library/Logs/bitwarden-use/reveal.log`; elsewhere
//! `$XDG_DATA_HOME/bitwarden-use/reveal.log`. One JSON object per line, 0600.

use std::io::Write as _;

#[derive(Debug, serde::Serialize)]
pub struct Reveal<'a> {
    pub ts: String,
    pub cmd: &'a str,
    pub item: &'a str,
    pub id: Option<&'a str>,
    pub field: Option<&'a str>,
    pub folder: Option<&'a str>,
    /// Process chain that asked, nearest first, e.g. "zsh < claude < iTerm2".
    pub caller: String,
    /// "unrestricted" (no reveal_folders set), "folder-allowlist", "touch-id",
    /// or "trusted-device" (`require_touch_id` is false).
    pub auth: &'a str,
}

pub fn log_path() -> anyhow::Result<std::path::PathBuf> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| anyhow::anyhow!("home directory unavailable"))?;
    let dir = if cfg!(target_os = "macos") {
        base.home_dir().join("Library/Logs/bitwarden-use")
    } else {
        base.data_local_dir().join("bitwarden-use")
    };
    Ok(dir.join("reveal.log"))
}

pub fn now_rfc3339() -> String {
    humantime::format_rfc3339_seconds(std::time::SystemTime::now())
        .to_string()
}

/// Names of the parent processes, nearest first (up to three levels).
pub fn caller_chain() -> String {
    let mut names = Vec::new();
    let mut pid = std::os::unix::process::parent_id();
    for _ in 0..3 {
        if pid <= 1 {
            break;
        }
        let Ok(out) = std::process::Command::new("ps")
            .args(["-o", "ppid=,comm=", "-p", &pid.to_string()])
            .output()
        else {
            break;
        };
        let line = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let mut parts = line.splitn(2, char::is_whitespace);
        let ppid = parts.next().and_then(|p| p.trim().parse::<u32>().ok());
        let comm = parts.next().unwrap_or("").trim();
        if comm.is_empty() {
            break;
        }
        names.push(std::path::Path::new(comm).file_name().map_or_else(
            || comm.to_string(),
            |n| n.to_string_lossy().into(),
        ));
        match ppid {
            Some(p) => pid = p,
            None => break,
        }
    }
    if names.is_empty() {
        "unknown".to_string()
    } else {
        names.join(" < ")
    }
}

pub fn format_line(r: &Reveal<'_>) -> anyhow::Result<String> {
    Ok(serde_json::to_string(r)?)
}

pub fn record(r: &Reveal<'_>) -> anyhow::Result<()> {
    let path = log_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path)?;
    writeln!(f, "{}", format_line(r)?)?;
    Ok(())
}

/// How often and how recently each item was revealed, keyed by item id.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Usage {
    pub uses: u32,
    /// RFC 3339, so it sorts as text.
    pub last_used: String,
}

/// Usage per item id, read from the audit log. Used to put the account you
/// actually use first when several match. A missing log means no history.
pub fn usage() -> std::collections::HashMap<String, Usage> {
    log_path()
        .and_then(|p| Ok(std::fs::read_to_string(p)?))
        .map(|text| usage_from(&text))
        .unwrap_or_default()
}

pub fn usage_from(text: &str) -> std::collections::HashMap<String, Usage> {
    #[derive(serde::Deserialize)]
    struct Line {
        ts: String,
        id: Option<String>,
    }
    let mut out = std::collections::HashMap::<String, Usage>::new();
    for line in text.lines() {
        let Ok(Line { ts, id: Some(id) }) = serde_json::from_str(line) else {
            continue;
        };
        let u = out.entry(id).or_default();
        u.uses += 1;
        if ts > u.last_used {
            u.last_used = ts;
        }
    }
    out
}

#[test]
fn usage_counts_and_keeps_latest() {
    let log = concat!(
        r#"{"ts":"2026-09-01T00:00:00Z","cmd":"run","item":"a","id":"1"}"#,
        "\n",
        r#"{"ts":"2026-09-03T00:00:00Z","cmd":"run","item":"a","id":"1"}"#,
        "\nnot json\n",
        r#"{"ts":"2026-09-02T00:00:00Z","cmd":"get","item":"b","id":"2"}"#,
        "\n",
        r#"{"ts":"2026-09-04T00:00:00Z","cmd":"get","item":"c","id":null}"#,
    );
    let u = usage_from(log);
    assert_eq!(u.len(), 2);
    assert_eq!(u["1"].uses, 2);
    assert_eq!(u["1"].last_used, "2026-09-03T00:00:00Z");
    assert_eq!(u["2"].uses, 1);
}

#[test]
fn line_has_no_value_and_is_json() {
    let r = Reveal {
        ts: "2026-09-15T00:00:00Z".into(),
        cmd: "get",
        item: "router",
        id: Some("abc"),
        field: Some("password"),
        folder: Some("memory"),
        caller: "zsh < claude".into(),
        auth: "folder-allowlist",
    };
    let line = format_line(&r).unwrap();
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["item"], "router");
    assert_eq!(v["auth"], "folder-allowlist");
    assert!(v.get("value").is_none());
}
