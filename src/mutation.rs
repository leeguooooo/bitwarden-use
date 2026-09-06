//! Field-level optimistic updates of complete server ciphers.
#[cfg(test)]
use serde_json::json;
use serde_json::Value;

#[derive(Default)]
pub struct Patch {
    pub guards: Vec<(String, Value)>,
    pub changes: Vec<(String, Value)>,
}

fn subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => e
            .iter()
            .all(|(k, v)| subset(v, a.get(k).unwrap_or(&Value::Null))),
        (Value::Array(e), Value::Array(a)) => {
            e.len() == a.len() && e.iter().zip(a).all(|(e, a)| subset(e, a))
        }
        (Value::Array(e), Value::Null) if e.is_empty() => true,
        _ => expected == actual,
    }
}

impl Patch {
    pub fn change(&mut self, path: &str, old: Value, new: Value) {
        self.guards.push((path.to_owned(), old));
        self.changes.push((path.to_owned(), new));
    }

    pub fn apply(&self, cipher: &mut Value) -> crate::prelude::Result<()> {
        let fail = |message: &str| crate::error::Error::UnsafeWrite {
            message: message.into(),
        };
        for (path, expected) in &self.guards {
            if !subset(expected, cipher.pointer(path).unwrap_or(&Value::Null))
            {
                return Err(fail(
                    "entry changed on server; sync and review again",
                ));
            }
        }
        let revision = cipher
            .get("revisionDate")
            .filter(|v| v.is_string())
            .cloned()
            .ok_or_else(|| fail("server did not provide revisionDate"))?;
        let mut updated = cipher.clone();
        for (path, value) in &self.changes {
            let (parent, key) = path
                .rsplit_once('/')
                .ok_or_else(|| fail("invalid patch path"))?;
            let object = updated
                .pointer_mut(parent)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| fail("missing patch parent"))?;
            let mut value = value.clone();
            // Preserve unknown per-URI/per-field metadata on unchanged elements.
            let identity_key = match path.as_str() {
                "/login/uris" => Some("uri"),
                "/fields" => Some("name"),
                _ => None,
            };
            if let (Some(identity), Some(new), Some(old)) = (
                identity_key,
                value.as_array_mut(),
                object.get(key).and_then(Value::as_array),
            ) {
                for element in new {
                    if let Some(existing) = old.iter().find(|existing| {
                        existing.get(identity) == element.get(identity)
                    }) {
                        if let (Some(base), Some(changes)) =
                            (existing.as_object(), element.as_object())
                        {
                            let mut merged = base.clone();
                            merged.extend(changes.clone());
                            *element = Value::Object(merged);
                        }
                    }
                }
            }
            object.insert(key.to_owned(), value);
        }
        // GET attachments are a list; PUT uses a map. Keep every attachment key/name.
        if let Some(attachments) =
            updated.get("attachments").and_then(Value::as_array)
        {
            let mut mapped = serde_json::Map::new();
            for attachment in attachments {
                let id = attachment
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fail("attachment missing id"))?;
                let mut item = serde_json::Map::new();
                item.insert(
                    "fileName".into(),
                    attachment["fileName"].clone(),
                );
                item.insert("key".into(), attachment["key"].clone());
                mapped.insert(id.to_owned(), Value::Object(item));
            }
            updated.as_object_mut().unwrap().remove("attachments");
            updated["attachments2"] = Value::Object(mapped);
        }
        // Modern blob-encrypted items require a different crypto protocol.
        if updated
            .get("encryptedByKeyId")
            .is_some_and(|v| !v.is_null())
        {
            return Err(fail(
                "blob-encrypted cipher is not supported by this client",
            ));
        }
        updated["lastKnownRevisionDate"] = revision;
        *cipher = updated;
        Ok(())
    }
}

#[test]
fn preserves_unknown_fields_and_rejects_concurrent_edits() {
    let original = json!({"revisionDate":"2026-09-06T01:00:00Z", "key":"item-key", "favorite":true,
        "reprompt":1,"future":{"nested":true},"login":{"password":"old","totp":"seed","fido2Credentials":[{"keyValue":"passkey"}]}});
    let mut patch = Patch::default();
    patch.change("/login/password", json!("old"), json!("new"));
    let mut cipher = original.clone();
    patch.apply(&mut cipher).unwrap();
    assert_eq!(cipher["login"]["password"], "new");
    for key in ["key", "favorite", "reprompt", "future"] {
        assert_eq!(cipher[key], original[key]);
    }
    assert_eq!(
        cipher["login"]["fido2Credentials"],
        original["login"]["fido2Credentials"]
    );
    assert_eq!(cipher["login"]["totp"], "seed");
    let before = cipher.clone();
    assert!(patch.apply(&mut cipher).is_err());
    assert_eq!(cipher, before);
    let mut no_revision = json!({"login":{"password":"old"}});
    assert!(patch.apply(&mut no_revision).is_err());
}

#[test]
fn unknown_uri_metadata_survives_append() {
    let mut cipher = json!({"revisionDate":"now", "login":{"uris":[{"uri":"enc:a","match":1,"uriChecksum":"checksum"}]}});
    let mut patch = Patch::default();
    patch.change(
        "/login/uris",
        json!([{"uri":"enc:a","match":1}]),
        json!([{"uri":"enc:a","match":1},{"uri":"enc:b","match":3}]),
    );
    patch.apply(&mut cipher).unwrap();
    assert_eq!(cipher["login"]["uris"][0]["uriChecksum"], "checksum");
    assert_eq!(cipher["login"]["uris"].as_array().unwrap().len(), 2);
}
