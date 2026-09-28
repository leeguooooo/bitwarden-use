//! The daily update notice, end to end through the real binary. The cache is
//! seeded fresh so nothing touches the network, and `gen-completions` is used
//! because it needs no config, agent or vault.

use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const NOTICE_PREFIX: &str = "bitwarden-use 99.0.0 is available (you have ";

fn run(args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache/bitwarden-use");
    std::fs::create_dir_all(&cache).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::write(
        cache.join("update-check.json"),
        format!(r#"{{"checked_at": {now}, "latest": "99.0.0"}}"#),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bitwarden-use"));
    cmd.args(args)
        .env("HOME", dir.path())
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env_remove("CI")
        .env_remove("BITWARDEN_USE_NO_UPDATE_CHECK")
        .env_remove("USE_NO_UPDATE_CHECK");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

#[test]
fn notice_is_one_stderr_line_and_never_on_stdout() {
    let out = run(&["gen-completions", "bash"], &[]);
    assert!(out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(stderr.starts_with(NOTICE_PREFIX), "{stderr}");
    assert!(
        stderr.ends_with("). Upgrade: bitwarden-use upgrade\n"),
        "{stderr}"
    );
    assert!(!stdout.contains("is available"));
    assert!(!stdout.is_empty());
}

#[test]
fn opt_outs_and_skipped_invocations_print_nothing() {
    for (k, v) in [
        ("CI", "true"),
        ("BITWARDEN_USE_NO_UPDATE_CHECK", "1"),
        ("USE_NO_UPDATE_CHECK", "1"),
    ] {
        let out = run(&["gen-completions", "bash"], &[(k, v)]);
        assert!(out.stderr.is_empty(), "{k}: {:?}", out.stderr);
    }
    for args in [&["--version"][..], &["--help"], &["upgrade", "--help"]] {
        let out = run(args, &[]);
        assert!(out.status.success());
        let all = [out.stdout, out.stderr].concat();
        assert!(
            !String::from_utf8_lossy(&all).contains("is available"),
            "{args:?}"
        );
    }
}
