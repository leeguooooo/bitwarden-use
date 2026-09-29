use super::*;
use rbw::mutation::Patch;
use serde_json::{json, Value};

#[derive(Debug, Default, Clone, clap::Args)]
pub struct WriteOptions {
    /// Permit explicitly empty values or clearing existing fields.
    #[arg(long)]
    pub allow_empty: bool,
    /// Apply the masked preview without an interactive confirmation.
    #[arg(long, conflicts_with = "dry_run")]
    pub yes: bool,
    /// Print the masked preview without writing.
    #[arg(long)]
    pub dry_run: bool,
}

impl WriteOptions {
    pub fn nonempty(&self, name: &str, value: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.allow_empty || !value.trim().is_empty(),
            "empty {name} refused; use --allow-empty to clear explicitly"
        );
        Ok(())
    }
    pub fn confirm(
        &self,
        changes: &[(String, bool, bool)],
    ) -> anyhow::Result<bool> {
        if changes.is_empty() {
            eprintln!("No changes.");
            return Ok(false);
        }
        eprintln!("Proposed changes (values hidden):");
        for (field, before, after) in changes {
            eprintln!(
                "  {}: {} -> {}",
                field.escape_default(),
                if *before { "[set]" } else { "[empty]" },
                if *after { "[set]" } else { "[empty]" }
            );
        }
        if self.dry_run {
            return Ok(false);
        }
        if self.yes {
            return Ok(true);
        }
        use is_terminal::IsTerminal as _;
        anyhow::ensure!(
            std::io::stdin().is_terminal(),
            "confirmation required; review with --dry-run, then pass --yes"
        );
        eprint!("Apply these changes? [y/N] ");
        std::io::stderr().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        anyhow::ensure!(
            matches!(answer.trim(), "y" | "Y" | "yes"),
            "write cancelled"
        );
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum MatchMode {
    Base,
    Host,
    Exact,
    Regex,
    StartsWith,
    Never,
}
impl From<MatchMode> for rbw::api::UriMatchType {
    fn from(mode: MatchMode) -> Self {
        match mode {
            MatchMode::Base => Self::Domain,
            MatchMode::Host => Self::Host,
            MatchMode::Exact => Self::Exact,
            MatchMode::Regex => Self::RegularExpression,
            MatchMode::StartsWith => Self::StartsWith,
            MatchMode::Never => Self::Never,
        }
    }
}

#[derive(Debug, Default, Clone, clap::Args)]
pub struct SetFields {
    #[arg(long)]
    pub totp: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub password: Option<String>,
    /// Replace all URIs; repeat for multiple values.
    #[arg(long = "uri", conflicts_with_all = ["uri_add", "uri_remove"])]
    pub uris: Vec<String>,
    #[arg(long)]
    pub uri_add: Vec<String>,
    #[arg(long)]
    pub uri_remove: Vec<String>,
    /// Matching mode for replacement or added URIs; defaults to base.
    #[arg(long = "match", value_enum)]
    pub match_mode: Option<MatchMode>,
    #[arg(long)]
    pub notes: Option<String>,
    /// Set an exact custom field name: NAME=VALUE. New fields are hidden.
    #[arg(long = "field")]
    pub custom: Vec<String>,
}

fn validate_uri(uri: &str, mode: Option<MatchMode>) -> anyhow::Result<()> {
    if mode == Some(MatchMode::Regex) {
        anyhow::ensure!(
            regex::Regex::new(uri).is_ok(),
            "invalid URI regular expression"
        );
    } else {
        let valid = url::Url::parse(uri).is_ok_and(|u| {
            u.host_str().is_some()
                && matches!(u.scheme(), "https" | "http")
                && u.username().is_empty()
                && u.password().is_none()
        });
        anyhow::ensure!(
            valid,
            "URI must be an http(s) URL without embedded credentials"
        );
    }
    Ok(())
}

impl SetFields {
    fn validate(&self, options: &WriteOptions) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.totp.is_some()
                || self.username.is_some()
                || self.password.is_some()
                || self.notes.is_some()
                || !self.uris.is_empty()
                || !self.uri_add.is_empty()
                || !self.uri_remove.is_empty()
                || !self.custom.is_empty(),
            "nothing to set"
        );
        anyhow::ensure!(
            self.match_mode.is_none()
                || !self.uris.is_empty()
                || !self.uri_add.is_empty(),
            "--match requires --uri or --uri-add"
        );
        for (name, value) in [
            ("totp", &self.totp),
            ("username", &self.username),
            ("password", &self.password),
            ("notes", &self.notes),
        ] {
            if let Some(value) = value {
                options.nonempty(name, value)?;
            }
        }
        if let Some(seed) = self.totp.as_deref().filter(|v| !v.is_empty()) {
            anyhow::ensure!(
                generate_totp(seed).is_ok(),
                "invalid TOTP seed or otpauth URI"
            );
        }
        for uri in self.uris.iter().chain(&self.uri_add) {
            if uri.is_empty() {
                options.nonempty("URI", uri)?;
            } else {
                validate_uri(uri, self.match_mode)?;
            }
        }
        anyhow::ensure!(
            !self.uri_add.iter().any(String::is_empty),
            "--uri-add cannot add an empty URI"
        );
        anyhow::ensure!(
            !self.uri_remove.iter().any(String::is_empty),
            "--uri-remove cannot select an empty URI"
        );
        anyhow::ensure!(
            !self.uris.iter().any(String::is_empty) || self.uris.len() == 1,
            "empty URI cannot be combined with other URIs"
        );
        let mut seen = std::collections::HashSet::new();
        for field in &self.custom {
            let (name, value) = field
                .split_once('=')
                .context("--field expects NAME=VALUE")?;
            anyhow::ensure!(
                !name.trim().is_empty() && seen.insert(name),
                "empty or repeated custom field name"
            );
            options.nonempty("custom field", value)?;
        }
        Ok(())
    }
}

fn uri_json(uris: &[rbw::db::Uri]) -> Value {
    json!(uris
        .iter()
        .map(|u| json!({"uri":u.uri,"match":u.match_type}))
        .collect::<Vec<_>>())
}
fn field_json(fields: &[rbw::db::Field]) -> Value {
    json!(fields.iter().map(|f| json!({"name":f.name,"value":f.value,"type":f.ty,"linkedId":f.linked_id})).collect::<Vec<_>>())
}

/// Build a patch without touching a server. The callback encrypts with the entry's own key.
fn plan(
    entry: &rbw::db::Entry,
    plain: &DecryptedCipher,
    fields: &SetFields,
    options: &WriteOptions,
    mut encrypt: impl FnMut(&str) -> anyhow::Result<String>,
) -> anyhow::Result<(Patch, Vec<(String, bool, bool)>)> {
    fields.validate(options)?;
    let rbw::db::EntryData::Login {
        username,
        password,
        totp,
        uris,
        ..
    } = &entry.data
    else {
        anyhow::bail!("set requires a login entry");
    };
    let DecryptedData::Login {
        username: old_user,
        password: old_pw,
        totp: old_totp,
        uris: old_uris,
    } = &plain.data
    else {
        anyhow::bail!("set requires a login entry");
    };
    let mut patch = Patch::default();
    // A changed item key/organization invalidates every newly encrypted value.
    patch.guards.push(("/key".into(), json!(entry.key)));
    patch
        .guards
        .push(("/organizationId".into(), json!(entry.org_id)));
    let mut preview = vec![];
    for (name, new, old, encrypted) in [
        ("username", &fields.username, old_user, username),
        ("password", &fields.password, old_pw, password),
        ("totp", &fields.totp, old_totp, totp),
        ("notes", &fields.notes, &plain.notes, &entry.notes),
    ] {
        if let Some(new) = new {
            anyhow::ensure!(
                encrypted.is_none() || old.is_some(),
                "cannot update a field that failed to decrypt"
            );
            if new == old.as_deref().unwrap_or("") {
                continue;
            }
            let new_cipher = if new.is_empty() {
                None
            } else {
                Some(encrypt(new)?)
            };
            let path = if name == "notes" {
                "/notes".into()
            } else {
                format!("/login/{name}")
            };
            patch.change(&path, json!(encrypted), json!(new_cipher));
            preview.push((name.to_owned(), old.is_some(), !new.is_empty()));
            if name == "password" {
                let old_history = json!(entry.history.iter().map(|h| json!({"lastUsedDate":h.last_used_date,"password":h.password})).collect::<Vec<_>>());
                let mut history = old_history.as_array().unwrap().clone();
                if let Some(password) = password {
                    history.insert(0, json!({"lastUsedDate": humantime::format_rfc3339(std::time::SystemTime::now()).to_string(), "password": password}));
                }
                patch.change("/passwordHistory", old_history, json!(history));
            }
        }
    }
    if !fields.uris.is_empty()
        || !fields.uri_add.is_empty()
        || !fields.uri_remove.is_empty()
    {
        let old = old_uris.clone().unwrap_or_default();
        anyhow::ensure!(
            old.len() == uris.len(),
            "cannot update URIs that failed to decrypt"
        );
        let mut updated = if fields.uris.is_empty() {
            old.clone()
        } else {
            fields
                .uris
                .iter()
                .filter(|u| !u.is_empty())
                .map(|u| DecryptedUri {
                    uri: u.clone(),
                    match_type: Some(
                        fields.match_mode.unwrap_or(MatchMode::Base).into(),
                    ),
                })
                .collect()
        };
        for remove in &fields.uri_remove {
            anyhow::ensure!(
                updated.iter().any(|u| &u.uri == remove),
                "URI to remove was not found"
            );
            updated.retain(|u| &u.uri != remove);
        }
        for add in &fields.uri_add {
            let uri = DecryptedUri {
                uri: add.clone(),
                match_type: Some(
                    fields.match_mode.unwrap_or(MatchMode::Base).into(),
                ),
            };
            if !updated.iter().any(|u| {
                u.uri == uri.uri
                    && u.match_type.unwrap_or(rbw::api::UriMatchType::Domain)
                        == uri
                            .match_type
                            .unwrap_or(rbw::api::UriMatchType::Domain)
            }) {
                updated.push(uri);
            }
        }
        anyhow::ensure!(
            options.allow_empty || !updated.is_empty(),
            "clearing all URIs requires --allow-empty"
        );
        if serde_json::to_value(&updated)? != serde_json::to_value(&old)? {
            let mut encrypted = Vec::new();
            for u in updated {
                // Preserve untouched URI ciphertext as well as matching metadata.
                if let Some(index) = old.iter().position(|o| {
                    o.uri == u.uri && o.match_type == u.match_type
                }) {
                    encrypted.push(uris[index].clone());
                } else {
                    encrypted.push(rbw::db::Uri {
                        uri: encrypt(&u.uri)?,
                        match_type: u.match_type,
                    });
                }
            }
            preview.push((
                "uris".into(),
                !uris.is_empty(),
                !encrypted.is_empty(),
            ));
            patch.change("/login/uris", uri_json(uris), uri_json(&encrypted));
        }
    }
    let mut custom = entry.fields.clone();
    for field in &fields.custom {
        let (name, value) = field.split_once('=').unwrap();
        let matches: Vec<_> = plain
            .fields
            .iter()
            .enumerate()
            .filter(|(_, f)| f.name.as_deref() == Some(name))
            .collect();
        anyhow::ensure!(matches.len() <= 1, "ambiguous custom field name");
        let old = matches.first().and_then(|(_, f)| f.value.as_deref());
        if matches.len() == 1 && old.unwrap_or("") == value {
            continue;
        }
        let new = if value.is_empty() {
            None
        } else {
            Some(encrypt(value)?)
        };
        if let Some((index, _)) = matches.first() {
            anyhow::ensure!(
                custom[*index].ty != Some(rbw::api::FieldType::Linked),
                "linked fields cannot be assigned a literal value"
            );
            if custom[*index].ty == Some(rbw::api::FieldType::Boolean) {
                anyhow::ensure!(
                    matches!(value, "true" | "false"),
                    "boolean custom fields require true or false"
                );
            }
            custom[*index].value = new;
        } else {
            custom.push(rbw::db::Field {
                name: Some(encrypt(name)?),
                value: new,
                ty: Some(rbw::api::FieldType::Hidden),
                linked_id: None,
            });
        }
        preview.push((
            format!("field:{name}"),
            old.is_some(),
            !value.is_empty(),
        ));
    }
    if custom != entry.fields {
        patch.change(
            "/fields",
            field_json(&entry.fields),
            field_json(&custom),
        );
    }
    Ok((patch, preview))
}

pub fn set(
    name: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    fields: SetFields,
    options: &WriteOptions,
) -> anyhow::Result<()> {
    fields.validate(options)?; // Reject missing/empty input before any unlock or network operation.
    unlock_online()?;
    let mut db = load_db()?;
    let (entry, plain) = find_entry(&db, name, user, folder, ignore_case)?;
    let (patch, preview) = plan(&entry, &plain, &fields, options, |value| {
        crate::actions::encrypt_entry(
            value,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )
    })?;
    if !options.confirm(&preview)? {
        return Ok(());
    }
    apply(&mut db, &entry.id, &patch)
}

fn apply(
    db: &mut rbw::db::Db,
    id: &str,
    patch: &Patch,
) -> anyhow::Result<()> {
    let (token, ()) = rbw::actions::patch_cipher(
        db.access_token.as_deref().context("missing access token")?,
        db.refresh_token
            .as_deref()
            .context("missing refresh token")?,
        id,
        patch,
    )?;
    if let Some(token) = token {
        db.access_token = Some(token);
        save_db(db)?;
    }
    crate::actions::sync()
        .context("write accepted, but sync failed; sync before retrying")?;
    eprintln!("Saved.");
    Ok(())
}

pub fn edit(
    name: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
    options: &WriteOptions,
) -> anyhow::Result<()> {
    let input = rbw::edit::read_stdin(options.allow_empty)?;
    unlock_online()?;
    let mut db = load_db()?;
    let (entry, plain) = find_entry(&db, name, user, folder, ignore_case)?;
    let (patch, preview) = match &plain.data {
        DecryptedData::Login { password, .. } => {
            let text = format!(
                "{}\n\n{}",
                password.as_deref().unwrap_or(""),
                plain.notes.as_deref().unwrap_or("")
            );
            let text = match input {
                Some(input) => input,
                None => rbw::edit::edit_with_options(
                    &text,
                    HELP_PW,
                    options.allow_empty,
                )?,
            };
            let (pw, notes) = parse_editor(&text);
            let fields = SetFields {
                password: Some(pw.unwrap_or_default()),
                notes: if notes.is_some() || plain.notes.is_some() {
                    Some(notes.unwrap_or_default())
                } else {
                    None
                },
                ..Default::default()
            };
            plan(&entry, &plain, &fields, options, |value| {
                crate::actions::encrypt_entry(
                    value,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
            })?
        }
        DecryptedData::SecureNote => {
            anyhow::ensure!(
                entry.notes.is_none() || plain.notes.is_some(),
                "cannot edit notes that failed to decrypt"
            );
            let text = match input {
                Some(input) => input,
                None => rbw::edit::edit_with_options(
                    plain.notes.as_deref().unwrap_or(""),
                    HELP_NOTES,
                    options.allow_empty,
                )?,
            };
            let (_, notes) = parse_editor(&format!("\n{text}"));
            options.nonempty("notes", notes.as_deref().unwrap_or(""))?;
            let mut patch = Patch::default();
            let mut preview = Vec::new();
            if notes != plain.notes {
                let encrypted = notes
                    .as_deref()
                    .map(|value| {
                        crate::actions::encrypt_entry(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?;
                patch.guards.push(("/key".into(), json!(entry.key)));
                patch
                    .guards
                    .push(("/organizationId".into(), json!(entry.org_id)));
                patch.change("/notes", json!(entry.notes), json!(encrypted));
                preview.push((
                    "notes".into(),
                    entry.notes.is_some(),
                    notes.is_some(),
                ));
            }
            (patch, preview)
        }
        _ => anyhow::bail!("edit supports login and secure-note entries"),
    };
    if !options.confirm(&preview)? {
        return Ok(());
    }
    apply(&mut db, &entry.id, &patch)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (rbw::db::Entry, DecryptedCipher) {
        let uri = rbw::db::Uri {
            uri: "enc:old-uri".into(),
            match_type: Some(rbw::api::UriMatchType::Host),
        };
        let entry = rbw::db::Entry {
            id: "id".into(),
            org_id: None,
            folder: None,
            folder_id: None,
            name: "enc:name".into(),
            key: Some("key".into()),
            master_password_reprompt: rbw::api::CipherRepromptType::None,
            notes: Some("enc:notes".into()),
            fields: vec![],
            history: vec![],
            data: rbw::db::EntryData::Login {
                username: Some("enc:user".into()),
                password: Some("enc:password".into()),
                totp: None,
                uris: vec![uri],
                fido2_credentials: vec![],
            },
        };
        let plain = DecryptedCipher {
            id: "id".into(),
            name: "name".into(),
            folder: None,
            fields: vec![],
            notes: Some("notes".into()),
            history: vec![],
            data: DecryptedData::Login {
                username: Some("user".into()),
                password: Some("password".into()),
                totp: None,
                uris: Some(vec![DecryptedUri {
                    uri: "https://old.example.com".into(),
                    match_type: Some(rbw::api::UriMatchType::Host),
                }]),
            },
        };
        (entry, plain)
    }
    #[test]
    fn reject_empty_before_encrypting() {
        let (entry, plain) = fixture();
        let fields = SetFields {
            password: Some(String::new()),
            ..Default::default()
        };
        assert!(plan(
            &entry,
            &plain,
            &fields,
            &WriteOptions::default(),
            |_| panic!("must not encrypt")
        )
        .is_err());
        let (patch, _) = plan(
            &entry,
            &plain,
            &fields,
            &WriteOptions {
                allow_empty: true,
                ..Default::default()
            },
            |_| panic!("clearing needs no encryption"),
        )
        .unwrap();
        assert!(patch
            .changes
            .contains(&("/login/password".into(), Value::Null)));
    }
    #[test]
    fn uri_add_preserves_other_ciphertext_and_mode() {
        let (entry, plain) = fixture();
        let fields = SetFields {
            uri_add: vec!["https://new.example.com".into()],
            match_mode: Some(MatchMode::Exact),
            ..Default::default()
        };
        let (patch, preview) =
            plan(&entry, &plain, &fields, &WriteOptions::default(), |v| {
                Ok(format!("enc:{v}"))
            })
            .unwrap();
        assert_eq!(patch.changes.len(), 1);
        assert_eq!(patch.changes[0].0, "/login/uris");
        assert_eq!(
            patch.changes[0].1[0],
            json!({"uri":"enc:old-uri","match":rbw::api::UriMatchType::Host})
        );
        assert_eq!(
            patch.changes[0].1[1]["match"],
            json!(rbw::api::UriMatchType::Exact)
        );
        assert_eq!(preview, [("uris".into(), true, true)]);
    }
    #[test]
    fn removal_and_totp_validation() {
        let (entry, plain) = fixture();
        let fields = SetFields {
            uri_remove: vec!["https://old.example.com".into()],
            ..Default::default()
        };
        assert!(plan(
            &entry,
            &plain,
            &fields,
            &WriteOptions::default(),
            |_| unreachable!()
        )
        .is_err());
        assert!(plan(
            &entry,
            &plain,
            &fields,
            &WriteOptions {
                allow_empty: true,
                ..Default::default()
            },
            |_| unreachable!()
        )
        .is_ok());
        let invalid = SetFields {
            totp: Some("invalid!".into()),
            ..Default::default()
        };
        assert!(invalid.validate(&WriteOptions::default()).is_err());
        let valid = SetFields {
            totp: Some("otpauth://totp/test?secret=JBSWY3DPEHPK3PXP".into()),
            ..Default::default()
        };
        let (patch, _) =
            plan(&entry, &plain, &valid, &WriteOptions::default(), |v| {
                Ok(format!("enc:{v}"))
            })
            .unwrap();
        assert_eq!(patch.changes.len(), 1);
        assert_eq!(patch.changes[0].0, "/login/totp");
    }
    #[test]
    fn custom_field_preserves_type_and_other_fields() {
        let (mut entry, mut plain) = fixture();
        entry.fields.push(rbw::db::Field {
            name: Some("enc:recovery".into()),
            value: Some("enc:old".into()),
            ty: Some(rbw::api::FieldType::Hidden),
            linked_id: None,
        });
        plain.fields.push(DecryptedField {
            name: Some("Recovery".into()),
            value: Some("old".into()),
            ty: Some(rbw::api::FieldType::Hidden),
        });
        let fields = SetFields {
            custom: vec!["Recovery=new".into()],
            ..Default::default()
        };
        let (patch, _) =
            plan(&entry, &plain, &fields, &WriteOptions::default(), |v| {
                Ok(format!("enc:{v}"))
            })
            .unwrap();
        assert_eq!(patch.changes.len(), 1);
        assert_eq!(patch.changes[0].0, "/fields");
        assert_eq!(patch.changes[0].1[0]["name"], "enc:recovery");
        assert_eq!(
            patch.changes[0].1[0]["type"],
            json!(rbw::api::FieldType::Hidden)
        );
        plain.fields.push(plain.fields[0].clone());
        assert!(plan(
            &entry,
            &plain,
            &fields,
            &WriteOptions::default(),
            |_| unreachable!()
        )
        .is_err());
    }

    #[test]
    fn dry_run_never_confirms_write() {
        let options = WriteOptions {
            dry_run: true,
            ..Default::default()
        };
        assert!(!options
            .confirm(&[("password".into(), true, true)])
            .unwrap());
    }
}
