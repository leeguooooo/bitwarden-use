use super::*;
use serde_json::{json, Value};

/// Mask all values; retain object shape, field names, and stable item IDs.
fn redact(value: &mut Value) {
    match value {
        Value::String(s) => *s = "[redacted]".into(),
        Value::Array(values) => values.iter_mut().for_each(redact),
        Value::Object(map) => {
            for (key, value) in map {
                if !matches!(
                    key.as_str(),
                    "id" | "name" | "type" | "match_type" | "last_used_date"
                ) {
                    redact(value);
                }
            }
        }
        _ => {}
    }
}

fn recovery_codes(notes: &str) -> Vec<String> {
    // Only entire code-shaped lines, optionally bullet/number prefixed. No prose scraping.
    let line = regex::Regex::new(r"^\s*(?:[-*•]\s+|[0-9]+[.)]\s+)?([A-Za-z0-9]{4,}(?:-[A-Za-z0-9]{4,})*)\s*$").unwrap();
    let mut result = Vec::new();
    for captures in notes.lines().filter_map(|s| line.captures(s)) {
        let code = &captures[1];
        if (8..=64).contains(&code.len())
            && code.bytes().any(|c| c.is_ascii_digit())
            && !result.iter().any(|v| v == code)
        {
            result.push(code.to_owned());
        }
    }
    result
}

pub(super) fn display(
    plain: &DecryptedCipher,
    field: Option<&str>,
    full: bool,
    json_output: bool,
    clipboard: bool,
    list_fields: bool,
    reveal: bool,
    codes: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(!clipboard || reveal, "--clipboard requires --reveal");
    if list_fields {
        plain.display_fields_list();
        return Ok(());
    }
    if codes {
        let codes = recovery_codes(plain.notes.as_deref().unwrap_or(""));
        anyhow::ensure!(
            !codes.is_empty(),
            "no standalone recovery-code lines found in notes"
        );
        let output = if reveal {
            json!(codes)
        } else {
            json!(codes.iter().map(|_| "[redacted]").collect::<Vec<_>>())
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }
    if json_output || full {
        let mut output = serde_json::to_value(plain)?;
        if !reveal {
            redact(&mut output);
        }
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }
    if let Some(field) = field {
        // Custom names are exact. Prefixing custom: disambiguates built-in names.
        let custom_name = field.strip_prefix("custom:").unwrap_or(field);
        if field.starts_with("custom:") || field.parse::<Field>().is_err() {
            let matches: Vec<_> = plain
                .fields
                .iter()
                .filter(|f| f.name.as_deref() == Some(custom_name))
                .collect();
            anyhow::ensure!(
                matches.len() == 1,
                "custom field missing or ambiguous; use its exact name"
            );
            let value = matches[0].value.as_deref().unwrap_or("");
            if !val_display_or_store(
                clipboard,
                if reveal { value } else { "[redacted]" },
            ) {
                anyhow::bail!("output failed");
            }
        } else if reveal {
            plain.display_field(&plain.id, field, clipboard);
        } else {
            println!("[redacted]");
        }
    } else if reveal {
        anyhow::ensure!(
            plain.display_short(&plain.id, clipboard),
            "entry has no password or output failed"
        );
    } else {
        println!("[redacted]");
    }
    Ok(())
}

fn target_url(domain: &str) -> anyhow::Result<url::Url> {
    let target = url::Url::parse(&if domain.contains("://") {
        domain.to_owned()
    } else {
        format!("https://{domain}")
    })
    .context("invalid domain or URL")?;
    anyhow::ensure!(
        matches!(target.scheme(), "https" | "http")
            && target.host_str().is_some()
            && target.username().is_empty()
            && target.password().is_none(),
        "domain must be an http(s) host or URL without credentials"
    );
    Ok(target)
}

fn domain_matches(
    stored: &str,
    mode: Option<rbw::api::UriMatchType>,
    target: &url::Url,
) -> bool {
    use rbw::api::UriMatchType as M;
    match mode.unwrap_or(M::Domain) {
        M::Domain => {
            let Ok(stored) = target_url(stored) else {
                return false;
            };
            let (Some(a), Some(b)) = (stored.host_str(), target.host_str())
            else {
                return false;
            };
            if a.parse::<std::net::IpAddr>().is_ok()
                || b.parse::<std::net::IpAddr>().is_ok()
            {
                return a == b;
            }
            a == b
                || matches!((psl::domain_str(a), psl::domain_str(b)), (Some(a), Some(b)) if a == b)
        }
        M::Host => target_url(stored).is_ok_and(|u| {
            u.host_str() == target.host_str()
                && u.port_or_known_default() == target.port_or_known_default()
        }),
        _ => matches_url(stored, mode, target),
    }
}

fn candidate_matches(
    item: &DecryptedSearchCipher,
    target: &url::Url,
    name: Option<&str>,
    user: Option<&str>,
) -> bool {
    item.entry_type == "Login"
        && name.is_none_or(|n| item.name == n || item.id == n)
        && user.is_none_or(|u| item.user.as_deref() == Some(u))
        && item
            .uris
            .iter()
            .any(|(uri, mode)| domain_matches(uri, *mode, target))
}

pub fn domain_login(
    domain: &str,
    name: Option<&str>,
    user: Option<&str>,
    reveal: bool,
) -> anyhow::Result<()> {
    let target = target_url(domain)?;
    unlock()?;
    let db = load_db()?;
    let candidates = db
        .entries
        .iter()
        .map(|entry| Ok((entry, decrypt_search_cipher(entry)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let candidates: Vec<_> = candidates
        .into_iter()
        .filter(|(_, c)| candidate_matches(c, &target, name, user))
        .collect();
    if candidates.len() != 1 {
        let list: Vec<_> = candidates.iter().map(|(_, c)| json!({"id":c.id,"name":c.name,"username":"[redacted]"})).collect();
        // stdout stays empty on ambiguity, even when --reveal was passed.
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&json!({"candidates":list}))?
        );
        anyhow::bail!("expected one domain match, found {}; use --name (exact name or UUID) and/or --user", candidates.len());
    }
    let plain = decrypt_cipher(candidates[0].0)?;
    let DecryptedData::Login {
        username,
        password,
        totp,
        ..
    } = plain.data
    else {
        anyhow::bail!("not a login entry");
    };
    let output = if reveal {
        json!({"id":plain.id,"name":plain.name,"username":username,"password":password,"code":totp.as_deref().map(generate_totp).transpose()?})
    } else {
        json!({"id":plain.id,"name":plain.name,"username":username.map(|_| "[redacted]"),"password":password.map(|_| "[redacted]"),"code":totp.map(|_| "[redacted]")})
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[test]
fn domain_boundaries() {
    use rbw::api::UriMatchType as M;
    let url = target_url("rasens-immi.moj.go.jp").unwrap();
    assert!(domain_matches(
        "https://www.ens-immi.moj.go.jp",
        Some(M::Domain),
        &url
    ));
    assert!(!domain_matches(
        "https://www.ens-immi.moj.go.jp",
        Some(M::Host),
        &url
    ));
    assert!(!domain_matches("https://moj.go.jp.evil.test", None, &url));
    assert!(!domain_matches("https://go.jp", None, &url));
    assert!(!domain_matches(
        "https://a.github.io",
        None,
        &target_url("b.github.io").unwrap()
    ));
    assert!(!domain_matches(
        "https://rasens-immi.moj.go.jp",
        Some(M::Never),
        &url
    ));
    assert!(target_url("https://user:password@example.com").is_err());
    assert!(!domain_matches(
        "https://127.1.0.1",
        None,
        &target_url("127.2.0.1").unwrap()
    ));
    assert!(domain_matches(
        "http://127.0.0.1",
        None,
        &target_url("127.0.0.1").unwrap()
    ));
}

#[test]
fn codes_and_redaction() {
    assert_eq!(recovery_codes("Recovery codes:\n1. 1234567890-1234567890\n- abcd1234\nDo not match 1234567890\n1234567890-1234567890"), ["1234567890-1234567890", "abcd1234"]);
    let mut data = json!({"id":"uuid","name":"label","data":{"password":"secret","username":"email","totp":"seed","uris":[{"uri":"https://x/?token=secret"}]},"notes":"codes","fields":[{"name":"recovery","value":"secret"}],"history":[{"password":"old"}]});
    redact(&mut data);
    let text = data.to_string();
    for secret in ["secret", "email", "seed", "codes", "https://", "old"] {
        assert!(!text.contains(secret));
    }
    assert_eq!(data["fields"][0]["name"], "recovery");
}

#[test]
fn candidates_require_exact_filters() {
    let c = DecryptedSearchCipher {
        id: "uuid-1".into(),
        entry_type: "Login".into(),
        folder: None,
        name: "Example production".into(),
        user: Some("alice@example.com".into()),
        uris: vec![("https://login.example.com".into(), None)],
        fields: vec![],
        notes: None,
    };
    let target = target_url("example.com").unwrap();
    assert!(candidate_matches(&c, &target, None, None));
    assert!(candidate_matches(&c, &target, Some("uuid-1"), None));
    assert!(!candidate_matches(&c, &target, Some("Example"), None));
    assert!(!candidate_matches(&c, &target, None, Some("alice")));
    assert!(!candidate_matches(
        &c,
        &target,
        None,
        Some("wrong@example.com")
    ));
    assert!(!candidate_matches(
        &c,
        &target_url("unrelated.com").unwrap(),
        Some("uuid-1"),
        None
    ));
}

#[test]
fn malformed_totp_parameters_do_not_panic() {
    for secret in [
        "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&period=0",
        "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&digits=99",
        "steam:",
    ] {
        assert!(generate_totp(secret).is_err());
    }
}
