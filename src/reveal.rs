//! Who may see plaintext without the owner at the keyboard.
//!
//! `reveal_folders` (config) lists folders whose items may be revealed by any
//! local process — the place to keep secrets an AI agent is allowed to use.
//! Items elsewhere need Touch ID each time. When the list is empty the old
//! behaviour stays (no gate). Every reveal is written to the audit log.

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Unrestricted,
    Allowed,
    NeedsConfirmation,
}

/// Folder names match case-insensitively; `a` also covers `a/b` (Bitwarden
/// nested folders are named with slashes).
pub fn decide(allowed: &[String], folder: Option<&str>) -> Decision {
    if allowed.is_empty() {
        return Decision::Unrestricted;
    }
    let Some(folder) = folder else {
        return Decision::NeedsConfirmation;
    };
    let f = folder.to_lowercase();
    let ok = allowed.iter().any(|a| {
        let a = a.trim().to_lowercase();
        !a.is_empty() && (f == a || f.starts_with(&format!("{a}/")))
    });
    if ok {
        Decision::Allowed
    } else {
        Decision::NeedsConfirmation
    }
}

/// Gate + audit for one reveal. Call right before plaintext leaves the process.
pub fn authorize(
    cmd: &str,
    item: &str,
    id: Option<&str>,
    field: Option<&str>,
    folder: Option<&str>,
) -> anyhow::Result<()> {
    authorize_fields(cmd, item, id, &[field], folder)
}

/// Like [`authorize`] for several fields of one item: a single confirmation
/// names them all, and each field gets its own audit line.
pub fn authorize_fields(
    cmd: &str,
    item: &str,
    id: Option<&str>,
    fields: &[Option<&str>],
    folder: Option<&str>,
) -> anyhow::Result<()> {
    let config = crate::config::Config::load()
        .unwrap_or_else(|_| crate::config::Config::new());
    let caller = crate::audit::caller_chain();
    let named: Vec<&str> = fields.iter().flatten().copied().collect();
    let auth = match decide(&config.reveal_folders, folder) {
        Decision::Unrestricted => "unrestricted",
        Decision::Allowed => "folder-allowlist",
        Decision::NeedsConfirmation => {
            crate::touchid::confirm(&format!(
                "reveal \"{item}\"{} to {caller}",
                if named.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", named.join(", "))
                }
            ))?;
            "touch-id"
        }
    };
    for field in fields {
        let entry = crate::audit::Reveal {
            ts: crate::audit::now_rfc3339(),
            cmd,
            item,
            id,
            field: *field,
            folder,
            caller: caller.clone(),
            auth,
        };
        if let Err(e) = crate::audit::record(&entry) {
            log::warn!("failed to write reveal audit log: {e:#}");
        }
    }
    Ok(())
}

#[test]
fn folder_policy() {
    let allow = vec!["memory".to_string(), "Agent".to_string()];
    assert_eq!(decide(&[], Some("x")), Decision::Unrestricted);
    assert_eq!(decide(&allow, Some("memory")), Decision::Allowed);
    assert_eq!(decide(&allow, Some("Memory/vpn")), Decision::Allowed);
    assert_eq!(decide(&allow, Some("agent")), Decision::Allowed);
    assert_eq!(
        decide(&allow, Some("memorybank")),
        Decision::NeedsConfirmation
    );
    assert_eq!(decide(&allow, Some("bank")), Decision::NeedsConfirmation);
    assert_eq!(decide(&allow, None), Decision::NeedsConfirmation);
    assert_eq!(
        decide(&[" ".to_string()], Some("x")),
        Decision::NeedsConfirmation
    );
}
