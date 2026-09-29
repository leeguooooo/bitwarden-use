//! `upgrade` end to end through the real binary, copied into a temp install
//! dir with a temp HOME. A fake install.sh (`BITWARDEN_USE_INSTALLER_URL`,
//! a file:// URL) stands in for the release download, so nothing real is
//! installed or replaced. `--tag` is used throughout: a pinned upgrade does
//! not depend on reaching the GitHub API.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    _dir: tempfile::TempDir,
    home: PathBuf,
    bin: PathBuf,
    installer: PathBuf,
}

fn fixture(with_agent: bool, installer_body: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let home = root.join("home");
    let bin = root.join("bin");
    std::fs::create_dir_all(home.join("tmp")).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::copy(
        env!("CARGO_BIN_EXE_bitwarden-use"),
        bin.join("bitwarden-use"),
    )
    .unwrap();
    if with_agent {
        std::fs::write(bin.join("bitwarden-use-agent"), "agent").unwrap();
    }
    // A copied skill folder: must be listed, never rewritten without --skills.
    let skill = home.join(".agents/skills/bitwarden-use");
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(skill.join("SKILL.md"), "local edits").unwrap();
    let installer = root.join("install.sh");
    std::fs::write(&installer, installer_body).unwrap();
    Fixture {
        _dir: dir,
        home,
        bin,
        installer,
    }
}

fn run(f: &Fixture, args: &[&str]) -> Output {
    Command::new(f.bin.join("bitwarden-use"))
        .arg("upgrade")
        .args(args)
        .env("HOME", &f.home)
        .env("XDG_CACHE_HOME", f.home.join(".cache"))
        // Never see the real agent: own profile, runtime and temp dirs.
        .env_remove("XDG_RUNTIME_DIR")
        .env("RBW_PROFILE", "upgrade-flow-test")
        .env("TMPDIR", f.home.join("tmp"))
        .env_remove("CARGO_HOME")
        .env(
            "BITWARDEN_USE_INSTALLER_URL",
            format!("file://{}", f.installer.display()),
        )
        .output()
        .unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn bytes(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

/// Installs a fake CLI reporting the version install.sh was asked for.
const GOOD_INSTALLER: &str = r#"#!/bin/sh
set -eu
v="${BITWARDEN_VERSION#v}"
printf '#!/bin/sh\necho "bitwarden-use %s"\n' "$v" > "$BITWARDEN_INSTALL_DIR/.new"
chmod +x "$BITWARDEN_INSTALL_DIR/.new"
mv -f "$BITWARDEN_INSTALL_DIR/.new" "$BITWARDEN_INSTALL_DIR/bitwarden-use"
"#;

#[test]
fn pinned_upgrade_installs_verifies_and_leaves_skills_alone() {
    let f = fixture(true, GOOD_INSTALLER);
    let out = run(&f, &["--tag", "v9.9.9"]);
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    assert!(stdout.contains("-> 9.9.9 (installed to"), "{stdout}");
    assert!(
        stdout.contains("not refreshed; pass --skills or run: npx skills update bitwarden-use"),
        "{stdout}"
    );
    assert_eq!(
        bytes(&f.home.join(".agents/skills/bitwarden-use/SKILL.md")),
        b"local edits"
    );
}

#[test]
fn failed_install_keeps_the_old_binary() {
    let f = fixture(
        true,
        "#!/bin/sh\necho 'install: checksum mismatch' >&2\nexit 1\n",
    );
    let before = bytes(&f.bin.join("bitwarden-use"));
    let out = run(&f, &["--tag", "v9.9.9"]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("unchanged"));
    assert_eq!(bytes(&f.bin.join("bitwarden-use")), before);
}

#[test]
fn wrong_version_after_install_is_not_success() {
    // Staged + renamed like the real installer: writing over the running
    // executable in place fails on Linux (ETXTBSY).
    let f = fixture(
        true,
        r#"#!/bin/sh
set -eu
d="$BITWARDEN_INSTALL_DIR"
printf '#!/bin/sh\necho bitwarden-use 1.0.0\n' > "$d/.new"
chmod +x "$d/.new"
mv -f "$d/.new" "$d/bitwarden-use"
"#,
    );
    let out = run(&f, &["--tag", "v9.9.9"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("expected 9.9.9"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn foreign_layout_is_refused_untouched() {
    // No bitwarden-use-agent next to the CLI: install.sh did not put it
    // there, so it is not ours to overwrite.
    let f =
        fixture(false, "#!/bin/sh\ntouch \"$BITWARDEN_INSTALL_DIR/ran\"\n");
    let before = bytes(&f.bin.join("bitwarden-use"));
    let out = run(&f, &["--tag", "v9.9.9"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stdout).contains("not replacing it"),
        "{}",
        text(&out.stdout)
    );
    assert!(!f.bin.join("ran").exists());
    assert_eq!(bytes(&f.bin.join("bitwarden-use")), before);
}

#[test]
fn json_reports_channel_agent_and_target() {
    let f = fixture(true, "#!/bin/sh\nexit 99\n");
    let out = run(&f, &["--json", "--tag", "v9.9.9"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["name"], "bitwarden-use");
    assert_eq!(v["install_channel"]["channel"], "installer");
    assert_eq!(v["install_channel"]["upgradable"], true);
    assert_eq!(v["agent"]["running"], false);
    assert_eq!(v["skills"][0]["channel"], "copied");
    // --json only reports: the installer (exit 99) never ran.
    assert!(f.bin.join("bitwarden-use").exists());
}

#[test]
fn bad_tag_is_rejected() {
    let f = fixture(true, GOOD_INSTALLER);
    let out = run(&f, &["--tag", "latest"]);
    assert_eq!(out.status.code(), Some(2));
}
