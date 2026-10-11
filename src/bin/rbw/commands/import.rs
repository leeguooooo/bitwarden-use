use super::*;
use std::io::Read as _;

/// One login read from another password manager's CSV export.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ImportedLogin {
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub totp: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParsedCsv {
    pub source: &'static str,
    pub logins: Vec<ImportedLogin>,
    pub empty_rows: usize,
}

// header names are matched case-insensitively. Apple Passwords / Safari:
// Title,URL,Username,Password,Notes,OTPAuth. Google Password Manager /
// Chrome: name,url,username,password,note. 1Password 8:
// Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes. The
// Bitwarden and LastPass names are accepted too.
const NAME: &[&str] = &["title", "name"];
const URI: &[&str] = &["url", "website", "login_uri"];
const USERNAME: &[&str] = &["username", "login_username"];
const PASSWORD: &[&str] = &["password", "login_password"];
const NOTES: &[&str] = &["notes", "note", "extra"];
const TOTP: &[&str] = &["otpauth", "totp", "login_totp"];

pub fn parse_csv(data: &[u8]) -> anyhow::Result<ParsedCsv> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let mut reader =
        csv::ReaderBuilder::new().flexible(true).from_reader(data);
    let headers: Vec<String> = reader
        .headers()
        .context("failed to read the CSV header")?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();
    let column = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| headers.iter().position(|h| h == name))
    };
    let (name, uri, username, password, notes, totp) = (
        column(NAME),
        column(URI),
        column(USERNAME),
        column(PASSWORD),
        column(NOTES),
        column(TOTP),
    );
    anyhow::ensure!(
        password.is_some() && (username.is_some() || uri.is_some()),
        "unrecognized CSV header ({}); expected an export from Apple \
         Passwords, Google Password Manager or 1Password",
        headers.join(",")
    );
    let has = |h: &str| headers.iter().any(|x| x == h);
    let source = if has("archived") && has("otpauth") {
        "1Password"
    } else if has("otpauth") {
        "Apple Passwords"
    } else if has("note") && has("name") {
        "Google Password Manager"
    } else {
        "CSV"
    };

    let mut parsed = ParsedCsv {
        source,
        logins: vec![],
        empty_rows: 0,
    };
    for (i, record) in reader.records().enumerate() {
        // row numbers as a spreadsheet shows them, counting the header
        let record = record
            .with_context(|| format!("failed to read row {}", i + 2))?;
        let field = |index: Option<usize>| {
            index
                .and_then(|index| record.get(index))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        let mut login = ImportedLogin {
            name: String::new(),
            username: field(username),
            password: field(password),
            uri: field(uri).map(|uri| normalize_android_uri(&uri)),
            totp: field(totp),
            notes: field(notes),
        };
        if login.username.is_none()
            && login.password.is_none()
            && login.totp.is_none()
        {
            parsed.empty_rows += 1;
            continue;
        }
        login.name = field(name)
            .or_else(|| {
                login.uri.as_deref().and_then(|uri| {
                    url::Url::parse(uri)
                        .ok()
                        .and_then(|u| u.host_str().map(str::to_string))
                })
            })
            .unwrap_or_else(|| "--".to_string());
        parsed.logins.push(login);
    }
    Ok(parsed)
}

// Chrome exports app logins as android://<hash>@<package>/, which Bitwarden
// stores as androidapp://<package>
fn normalize_android_uri(uri: &str) -> String {
    uri.strip_prefix("android://")
        .and_then(|rest| rest.split_once('@'))
        .map_or_else(
            || uri.to_string(),
            |(_, package)| {
                format!("androidapp://{}", package.trim_end_matches('/'))
            },
        )
}

fn dedup_key(name: &str, username: Option<&str>) -> (String, String) {
    (
        name.to_lowercase(),
        username.unwrap_or_default().to_lowercase(),
    )
}

pub fn import(
    file: &std::path::Path,
    folder: Option<&str>,
    options: &WriteOptions,
) -> anyhow::Result<()> {
    let data = if file.as_os_str() == "-" {
        let mut data = vec![];
        std::io::stdin().read_to_end(&mut data)?;
        data
    } else {
        std::fs::read(file)
            .with_context(|| format!("failed to read {}", file.display()))?
    };
    let parsed = parse_csv(&data)?;
    drop(data);

    unlock_online()?;
    let mut db = load_db()?;

    // skip logins that are already in the vault (same name and username)
    // and repeats within the file, so running an import twice is harmless
    let mut seen = std::collections::HashSet::new();
    for entry in &db.entries {
        let plain =
            decrypt_list_cipher(entry, &[ListField::Name, ListField::User])?;
        if let Some(name) = plain.name {
            seen.insert(dedup_key(&name, plain.user.as_deref()));
        }
    }
    let total = parsed.logins.len();
    let logins: Vec<_> = parsed
        .logins
        .into_iter()
        .filter(|l| seen.insert(dedup_key(&l.name, l.username.as_deref())))
        .collect();

    eprintln!(
        "{} export: {total} logins, {} already in the vault or repeated, {} \
         without a username or password",
        parsed.source,
        total - logins.len(),
        parsed.empty_rows
    );
    if logins.is_empty() {
        eprintln!("Nothing to import.");
        return Ok(());
    }
    eprintln!(
        "Will add {} logins{} (passwords hidden):",
        logins.len(),
        folder
            .map(|f| format!(" to folder {f:?}"))
            .unwrap_or_default()
    );
    for login in &logins {
        eprintln!(
            "  {}{}",
            login.name.escape_debug(),
            login
                .username
                .as_deref()
                .map(|u| format!(" ({})", u.escape_debug()))
                .unwrap_or_default()
        );
    }
    if !options.approve()? {
        return Ok(());
    }

    let refresh_token =
        db.refresh_token.clone().context("missing refresh token")?;
    let mut access_token =
        db.access_token.clone().context("missing access token")?;
    let folder_id = folder
        .map(|folder| {
            resolve_folder(&mut db, &mut access_token, &refresh_token, folder)
        })
        .transpose()?;

    let encrypt = |value: &Option<String>| {
        value
            .as_deref()
            .map(|value| crate::actions::encrypt(value, None))
            .transpose()
    };
    let mut failed = 0;
    for (i, login) in logins.iter().enumerate() {
        let result = (|| -> anyhow::Result<()> {
            let data = rbw::db::EntryData::Login {
                username: encrypt(&login.username)?,
                password: encrypt(&login.password)?,
                uris: encrypt(&login.uri)?
                    .map(|uri| rbw::db::Uri {
                        uri,
                        match_type: None,
                    })
                    .into_iter()
                    .collect(),
                totp: encrypt(&login.totp)?,
                fido2_credentials: vec![],
            };
            let (new_access_token, ()) = rbw::actions::add(
                &access_token,
                &refresh_token,
                &crate::actions::encrypt(&login.name, None)?,
                &data,
                encrypt(&login.notes)?.as_deref(),
                folder_id.as_deref(),
            )?;
            if let Some(new_access_token) = new_access_token {
                access_token.clone_from(&new_access_token);
                db.access_token = Some(new_access_token);
                save_db(&db)?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                eprintln!(
                    "[{}/{}] added {}",
                    i + 1,
                    logins.len(),
                    login.name.escape_debug()
                );
            }
            Err(e) => {
                failed += 1;
                eprintln!(
                    "[{}/{}] failed {}: {e:#}",
                    i + 1,
                    logins.len(),
                    login.name.escape_debug()
                );
            }
        }
    }

    crate::actions::sync()
        .context("import written, but sync failed; run `bwu sync`")?;
    anyhow::ensure!(
        failed == 0,
        "{failed} of {} logins failed to import; running the import again \
         adds only the missing ones",
        logins.len()
    );
    eprintln!("Imported {} logins.", logins.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_passwords_export() {
        let csv = "\u{feff}Title,URL,Username,Password,Notes,OTPAuth\n\
            example.com (alice),https://example.com/,alice,pw1,\"two\nlines\",otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n\
            ,,,,,\n";
        let parsed = parse_csv(csv.as_bytes()).unwrap();
        assert_eq!(parsed.source, "Apple Passwords");
        assert_eq!(parsed.empty_rows, 1);
        assert_eq!(
            parsed.logins,
            [ImportedLogin {
                name: "example.com (alice)".into(),
                username: Some("alice".into()),
                password: Some("pw1".into()),
                uri: Some("https://example.com/".into()),
                totp: Some("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP".into()),
                notes: Some("two\nlines".into()),
            }]
        );
    }

    #[test]
    fn google_password_manager_export() {
        let csv = "name,url,username,password,note\n\
            ,https://accounts.example.com/login,bob,pw2,\n\
            ,android://AbC123==@com.example.app/,carol,pw3,hi\n";
        let parsed = parse_csv(csv.as_bytes()).unwrap();
        assert_eq!(parsed.source, "Google Password Manager");
        assert_eq!(parsed.logins[0].name, "accounts.example.com");
        assert_eq!(parsed.logins[0].notes, None);
        assert_eq!(
            parsed.logins[1].uri.as_deref(),
            Some("androidapp://com.example.app")
        );
        assert_eq!(parsed.logins[1].name, "com.example.app");
        assert_eq!(parsed.logins[1].notes.as_deref(), Some("hi"));
    }

    #[test]
    fn onepassword_export() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
            Example,https://example.com,dave,pw4,,false,false,work,a note\n";
        let parsed = parse_csv(csv.as_bytes()).unwrap();
        assert_eq!(parsed.source, "1Password");
        assert_eq!(parsed.logins[0].name, "Example");
        assert_eq!(parsed.logins[0].totp, None);
        assert_eq!(parsed.logins[0].notes.as_deref(), Some("a note"));
    }

    #[test]
    fn unknown_header_is_rejected() {
        let err = parse_csv(b"foo,bar\n1,2\n").unwrap_err();
        assert!(err
            .to_string()
            .contains("unrecognized CSV header (foo,bar)"));
    }
}
