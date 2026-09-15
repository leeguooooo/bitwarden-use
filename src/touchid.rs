//! Human confirmation through macOS LocalAuthentication: Touch ID, with the
//! login password as a fallback (Macs without Touch ID, lid closed).
//!
//! Used before reading the master password from the Keychain and before
//! revealing an item outside `reveal_folders`, so a process that merely runs
//! as the user (a script, an AI agent) cannot read secrets without the owner
//! physically confirming.

/// Blocks until the owner confirms or cancels. `reason` is shown in the
/// system dialog, e.g. "unlock the Bitwarden vault".
pub fn confirm(reason: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        imp::confirm(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = reason;
        anyhow::bail!("Touch ID confirmation is only supported on macOS")
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    pub fn confirm(reason: &str) -> anyhow::Result<()> {
        let ctx = unsafe { LAContext::new() };
        let policy = LAPolicy::DeviceOwnerAuthentication;
        if let Err(e) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
            anyhow::bail!(
                "device owner authentication unavailable: {}",
                e.localizedDescription()
            );
        }
        let (tx, rx) = std::sync::mpsc::channel::<Option<String>>();
        let reply = RcBlock::new(move |ok: Bool, err: *mut NSError| {
            let outcome = if ok.as_bool() {
                None
            } else {
                Some(unsafe { err.as_ref() }.map_or_else(
                    || "denied".to_string(),
                    |e| e.localizedDescription().to_string(),
                ))
            };
            let _ = tx.send(outcome);
        });
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                policy,
                &NSString::from_str(reason),
                &reply,
            );
        }
        match rx.recv_timeout(std::time::Duration::from_secs(120)) {
            Ok(None) => Ok(()),
            Ok(Some(msg)) => anyhow::bail!("confirmation refused: {msg}"),
            Err(_) => anyhow::bail!("confirmation timed out"),
        }
    }
}
