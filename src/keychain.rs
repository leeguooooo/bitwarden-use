//! Explicit opt-in master-password storage, scoped to server, email and profile.
#[cfg(any(target_os = "macos", test))]
use anyhow::Context as _;

#[cfg(any(target_os = "macos", test))]
fn account(
    config: &crate::config::Config,
    profile: &str,
) -> anyhow::Result<String> {
    Ok(serde_json::to_string(&(
        profile,
        config
            .base_url
            .as_deref()
            .unwrap_or("https://api.bitwarden.com"),
        config.email.as_deref().context("email not configured")?,
    ))?)
}

#[cfg(target_os = "macos")]
fn login_keychain(
) -> anyhow::Result<security_framework::os::macos::keychain::SecKeychain> {
    let dirs =
        directories::BaseDirs::new().context("home directory unavailable")?;
    security_framework::os::macos::keychain::SecKeychain::open(
        dirs.home_dir().join("Library/Keychains/login.keychain-db"),
    )
    .context("cannot open macOS login keychain")
}

pub fn read() -> anyhow::Result<crate::locked::Password> {
    #[cfg(target_os = "macos")]
    {
        let config = crate::config::Config::load()?;
        let account = account(&config, &crate::dirs::profile())?;
        let (value, _) = login_keychain()?.find_generic_password("bitwarden-use.master-password", &account)
            .context("master password unavailable in login keychain; enroll with unlock --keychain-store")?;
        anyhow::ensure!(
            !value.is_empty() && value.len() <= 4096,
            "invalid keychain password length"
        );
        let mut bytes = crate::locked::Vec::new();
        bytes.extend(value.iter().copied());
        Ok(crate::locked::Password::new(bytes))
    }
    #[cfg(not(target_os = "macos"))]
    anyhow::bail!("--keychain is only supported on macOS")
}

/// Called only after the supplied password successfully decrypts the local vault.
pub fn store(password: &crate::locked::Password) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let config = crate::config::Config::load()?;
        let account = account(&config, &crate::dirs::profile())?;
        login_keychain()?
            .set_generic_password(
                "bitwarden-use.master-password",
                &account,
                password.password(),
            )
            .context("failed to save verified password in login keychain")
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = password;
        anyhow::bail!("--keychain is only supported on macOS")
    }
}

#[test]
fn identity_is_scoped_without_collisions() {
    let mut c = crate::config::Config::default();
    c.email = Some("test@example.com".into());
    let first = account(&c, "main").unwrap();
    assert_ne!(first, account(&c, "work").unwrap());
    c.base_url = Some("https://vault.example.com".into());
    assert_ne!(first, account(&c, "main").unwrap());
    c.email = None;
    assert!(account(&c, "main").is_err());
}
