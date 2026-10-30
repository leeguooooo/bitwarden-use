// serde_repr generates some as conversions that we can't seem to silence from
// here, unfortunately
#![allow(clippy::as_conversions)]

use crate::prelude::*;

use rand::distr::SampleString as _;
use sha2::Digest as _;
use tokio::io::AsyncReadExt as _;

use crate::json::{
    DeserializeJsonWithPath as _, DeserializeJsonWithPathAsync as _,
};

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl std::fmt::Display for UriMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::enum_glob_use)]
        use UriMatchType::*;
        let s = match self {
            Domain => "domain",
            Host => "host",
            StartsWith => "starts_with",
            Exact => "exact",
            RegularExpression => "regular_expression",
            Never => "never",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TwoFactorProviderType {
    pub fn message(&self) -> &str {
        match *self {
            Self::Authenticator => "Enter the 6 digit verification code from your authenticator app.",
            Self::Yubikey => "Insert your Yubikey and push the button.",
            Self::Email => "Enter the PIN you received via email.",
            _ => "Enter the code."
        }
    }

    pub fn header(&self) -> &str {
        match *self {
            Self::Authenticator => "Authenticator App",
            Self::Yubikey => "Yubikey",
            Self::Email => "Email Code",
            _ => "Two Factor Authentication",
        }
    }

    pub fn grab(&self) -> bool {
        !matches!(self, Self::Email)
    }
}

impl<'de> serde::Deserialize<'de> for TwoFactorProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TwoFactorProviderTypeVisitor;
        impl serde::de::Visitor<'_> for TwoFactorProviderTypeVisitor {
            type Value = TwoFactorProviderType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("two factor provider id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(TwoFactorProviderTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for TwoFactorProviderType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Authenticator),
            "1" => Ok(Self::Email),
            "2" => Ok(Self::Duo),
            "3" => Ok(Self::Yubikey),
            "4" => Ok(Self::U2f),
            "5" => Ok(Self::Remember),
            "6" => Ok(Self::OrganizationDuo),
            "7" => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider { ty: ty.to_string() }),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl<'de> serde::Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KdfTypeVisitor;
        impl serde::de::Visitor<'_> for KdfTypeVisitor {
            type Value = KdfType;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("kdf id")
            }

            fn visit_str<E>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(serde::de::Error::custom)
            }

            fn visit_u64<E>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                std::convert::TryFrom::try_from(value)
                    .map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_any(KdfTypeVisitor)
    }
}

impl std::convert::TryFrom<u64> for KdfType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl std::str::FromStr for KdfType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Pbkdf2),
            "1" => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType { ty: ty.to_string() }),
        }
    }
}

impl serde::Serialize for KdfType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::Pbkdf2 => "0",
            Self::Argon2id => "1",
        };
        serializer.serialize_str(s)
    }
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
)]
#[repr(u8)]
pub enum CipherRepromptType {
    None = 0,
    Password = 1,
}

#[derive(serde::Serialize, Debug)]
struct PreloginReq {
    email: String,
}

#[derive(serde::Deserialize, Debug)]
struct PreloginRes {
    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: KdfType,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenReq {
    grant_type: String,
    scope: String,
    client_id: String,
    #[serde(rename = "deviceType")]
    device_type: u32,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "deviceName")]
    device_name: String,
    #[serde(rename = "devicePushToken")]
    device_push_token: String,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(rename = "twoFactorProvider")]
    two_factor_provider: Option<u32>,
    #[serde(flatten)]
    auth: ConnectTokenAuth,
}

#[derive(serde::Serialize, Debug)]
#[serde(untagged)]
enum ConnectTokenAuth {
    Password(ConnectTokenPassword),
    AuthCode(ConnectTokenAuthCode),
    ClientCredentials(ConnectTokenClientCredentials),
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenPassword {
    username: String,
    password: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenAuthCode {
    code: String,
    code_verifier: String,
    redirect_uri: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectTokenClientCredentials {
    username: String,
    client_secret: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectTokenRes {
    access_token: String,
    refresh_token: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorRes {
    error: String,
    error_description: Option<String>,
    #[serde(rename = "ErrorModel", alias = "errorModel")]
    error_model: Option<ConnectErrorResErrorModel>,
    #[serde(rename = "TwoFactorProviders", alias = "twoFactorProviders")]
    two_factor_providers: Option<Vec<TwoFactorProviderType>>,
    #[serde(
        rename = "SsoEmail2faSessionToken",
        alias = "ssoEmail2faSessionToken"
    )]
    sso_email_2fa_session_token: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectErrorResErrorModel {
    #[serde(rename = "Message", alias = "message")]
    message: String,
}

#[derive(serde::Serialize, Debug)]
struct ConnectRefreshTokenReq {
    grant_type: String,
    client_id: String,
    refresh_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct ConnectRefreshTokenRes {
    access_token: String,
}

#[derive(serde::Serialize, Debug)]
struct SendEmailLoginReq {
    email: String,
    #[serde(rename = "DeviceIdentifier", alias = "deviceIdentifier")]
    device_identifier: String,
    #[serde(
        rename = "SsoEmail2faSessionToken",
        alias = "ssoEmail2faSessionToken"
    )]
    sso_email_2fa_session_token: String,
}

#[derive(serde::Deserialize, Debug)]
struct SyncRes {
    #[serde(rename = "Ciphers", alias = "ciphers")]
    ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile", alias = "profile")]
    profile: SyncResProfile,
    #[serde(rename = "Folders", alias = "folders")]
    folders: Vec<SyncResFolder>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResCipher {
    #[serde(rename = "Type", alias = "type", default)]
    ty: Option<u8>,

    #[serde(rename = "Attachments", alias = "attachments", default)]
    attachments: Option<Vec<crate::db::Attachment>>,
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "FolderId", alias = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "OrganizationId", alias = "organizationId")]
    organization_id: Option<String>,
    #[serde(rename = "Name", alias = "name")]
    name: String,
    #[serde(
        rename = "Login",
        alias = "login",
        default,
        deserialize_with = "deserialize_login"
    )]
    login: Option<CipherLogin>,
    #[serde(rename = "Card", alias = "card")]
    card: Option<CipherCard>,
    #[serde(rename = "Identity", alias = "identity")]
    identity: Option<CipherIdentity>,
    #[serde(rename = "SecureNote", alias = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "SshKey", alias = "sshKey")]
    ssh_key: Option<CipherSshKey>,
    #[serde(rename = "Notes", alias = "notes")]
    notes: Option<String>,
    #[serde(rename = "PasswordHistory", alias = "passwordHistory")]
    password_history: Option<Vec<SyncResPasswordHistory>>,
    #[serde(rename = "Fields", alias = "fields")]
    fields: Option<Vec<CipherField>>,
    #[serde(rename = "DeletedDate", alias = "deletedDate")]
    deleted_date: Option<String>,
    #[serde(rename = "Key", alias = "key")]
    key: Option<String>,
    #[serde(rename = "Reprompt", alias = "reprompt")]
    reprompt: CipherRepromptType,
}

impl SyncResCipher {
    fn to_entry(
        &self,
        folders: &[SyncResFolder],
    ) -> Option<crate::db::Entry> {
        if self.deleted_date.is_some() {
            return None;
        }
        let history =
            self.password_history
                .as_ref()
                .map_or_else(Vec::new, |history| {
                    history
                        .iter()
                        .filter_map(|entry| {
                            // Gets rid of entries with a non-existent
                            // password
                            entry.password.clone().map(|p| {
                                crate::db::HistoryEntry {
                                    last_used_date: entry
                                        .last_used_date
                                        .clone(),
                                    password: p,
                                }
                            })
                        })
                        .collect()
                });

        let (folder, folder_id) =
            self.folder_id.as_ref().map_or((None, None), |folder_id| {
                let mut folder_name = None;
                for folder in folders {
                    if &folder.id == folder_id {
                        folder_name = Some(folder.name.clone());
                    }
                }
                (folder_name, Some(folder_id))
            });
        let data = if let Some(login) = self
            .login
            .as_ref()
            .filter(|_| self.ty.is_none_or(|ty| ty == 1))
        {
            crate::db::EntryData::Login {
                username: login.username.clone(),
                password: login.password.clone(),
                totp: login.totp.clone(),
                uris: login.uris.as_ref().map_or_else(
                    std::vec::Vec::new,
                    |uris| {
                        uris.iter()
                            .filter_map(|uri| {
                                uri.uri.clone().map(|s| crate::db::Uri {
                                    uri: s,
                                    match_type: uri.match_type,
                                })
                            })
                            .collect()
                    },
                ),
                fido2_credentials: login
                    .fido2_credentials
                    .as_ref()
                    .map_or_else(std::vec::Vec::new, |creds| {
                        creds
                            .iter()
                            .map(|cred| crate::db::Fido2Credential {
                                credential_id: cred.credential_id.clone(),
                                key_type: cred.key_type.clone(),
                                key_algorithm: cred.key_algorithm.clone(),
                                key_curve: cred.key_curve.clone(),
                                key_value: cred.key_value.clone(),
                                rp_id: cred.rp_id.clone(),
                                rp_name: cred.rp_name.clone(),
                                user_handle: cred.user_handle.clone(),
                                user_name: cred.user_name.clone(),
                                counter: cred.counter.clone(),
                                discoverable: cred.discoverable.clone(),
                                creation_date: cred.creation_date.clone(),
                            })
                            .collect()
                    }),
            }
        } else if let Some(card) = self
            .card
            .as_ref()
            .filter(|_| self.ty.is_none_or(|ty| ty == 3))
        {
            crate::db::EntryData::Card {
                cardholder_name: card.cardholder_name.clone(),
                number: card.number.clone(),
                brand: card.brand.clone(),
                exp_month: card.exp_month.clone(),
                exp_year: card.exp_year.clone(),
                code: card.code.clone(),
            }
        } else if let Some(identity) = self
            .identity
            .as_ref()
            .filter(|_| self.ty.is_none_or(|ty| ty == 4))
        {
            crate::db::EntryData::Identity {
                title: identity.title.clone(),
                first_name: identity.first_name.clone(),
                middle_name: identity.middle_name.clone(),
                last_name: identity.last_name.clone(),
                address1: identity.address1.clone(),
                address2: identity.address2.clone(),
                address3: identity.address3.clone(),
                city: identity.city.clone(),
                state: identity.state.clone(),
                postal_code: identity.postal_code.clone(),
                country: identity.country.clone(),
                phone: identity.phone.clone(),
                email: identity.email.clone(),
                ssn: identity.ssn.clone(),
                license_number: identity.license_number.clone(),
                passport_number: identity.passport_number.clone(),
                username: identity.username.clone(),
            }
        } else if let Some(_secure_note) = self
            .secure_note
            .as_ref()
            .filter(|_| self.ty.is_none_or(|ty| ty == 2))
        {
            crate::db::EntryData::SecureNote
        } else if let Some(ssh_key) = self
            .ssh_key
            .as_ref()
            .filter(|_| self.ty.is_none_or(|ty| ty == 5))
        {
            crate::db::EntryData::SshKey {
                private_key: ssh_key.private_key.clone(),
                public_key: ssh_key.public_key.clone(),
                fingerprint: ssh_key.fingerprint.clone(),
            }
        } else {
            return None;
        };
        let fields = self.fields.as_ref().map_or_else(Vec::new, |fields| {
            fields
                .iter()
                .map(|field| crate::db::Field {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect()
        });
        Some(crate::db::Entry {
            id: self.id.clone(),
            org_id: self.organization_id.clone(),
            folder,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: self.name.clone(),
            data,
            fields,
            notes: self.notes.clone(),
            history,
            key: self.key.clone(),
            master_password_reprompt: self.reprompt,
            attachments: self.attachments.clone().unwrap_or_default(),
        })
    }
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfile {
    #[serde(rename = "Key", alias = "key")]
    key: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: String,
    #[serde(rename = "Organizations", alias = "organizations")]
    organizations: Vec<SyncResProfileOrganization>,
}

#[derive(serde::Deserialize, Debug)]
struct SyncResProfileOrganization {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
struct SyncResFolder {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

// written in camelCase like the official clients do. servers that keep the
// incoming keys and add their own camelCase copy (nodewarden) would otherwise
// hand back both `Uris` and `uris`; see `deserialize_login` for reading those.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLogin {
    #[serde(rename = "username", alias = "Username")]
    username: Option<String>,
    #[serde(rename = "password", alias = "Password")]
    password: Option<String>,
    #[serde(rename = "totp", alias = "Totp")]
    totp: Option<String>,
    #[serde(rename = "uris", alias = "Uris")]
    uris: Option<Vec<CipherLoginUri>>,
    // passkeys / webauthn credentials attached to this login. these are
    // dropped on serialization (skip_serializing_if) so that editing a login
    // through rbw does not accidentally clear them on the server.
    #[serde(
        rename = "fido2Credentials",
        alias = "Fido2Credentials",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    fido2_credentials: Option<Vec<CipherLoginFido2>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLoginUri {
    #[serde(rename = "uri", alias = "Uri")]
    uri: Option<String>,
    #[serde(rename = "match", alias = "Match")]
    match_type: Option<UriMatchType>,
}

// A FIDO2 (passkey) credential stored on a login cipher. The sensitive fields
// (key_value, rp_id, user_handle, ...) are EncStrings, encrypted with the same
// per-cipher/org key as the rest of the login, and are decrypted on demand by
// the agent just like username/password.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherLoginFido2 {
    #[serde(rename = "credentialId", alias = "CredentialId", default)]
    credential_id: Option<String>,
    #[serde(rename = "keyType", alias = "KeyType", default)]
    key_type: Option<String>,
    #[serde(rename = "keyAlgorithm", alias = "KeyAlgorithm", default)]
    key_algorithm: Option<String>,
    #[serde(rename = "keyCurve", alias = "KeyCurve", default)]
    key_curve: Option<String>,
    // PKCS#8 private key, base64url-encoded then encrypted (EncString).
    #[serde(rename = "keyValue", alias = "KeyValue", default)]
    key_value: Option<String>,
    #[serde(rename = "rpId", alias = "RpId", default)]
    rp_id: Option<String>,
    #[serde(rename = "rpName", alias = "RpName", default)]
    rp_name: Option<String>,
    #[serde(rename = "userHandle", alias = "UserHandle", default)]
    user_handle: Option<String>,
    #[serde(rename = "userName", alias = "UserName", default)]
    user_name: Option<String>,
    #[serde(rename = "counter", alias = "Counter", default)]
    counter: Option<String>,
    #[serde(rename = "discoverable", alias = "Discoverable", default)]
    discoverable: Option<String>,
    #[serde(rename = "creationDate", alias = "CreationDate", default)]
    creation_date: Option<String>,
}

// Read a login that may carry the same field twice in different case (`Uris`
// and `uris`), which serde would otherwise reject as a duplicate field and
// fail the whole sync. The camelCase copy wins unless it is null.
fn deserialize_login<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<CipherLogin>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;

    fn camel_keys(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (key, value) in map {
                    let mut chars = key.chars();
                    let camel = chars.next().map_or_else(String::new, |c| {
                        c.to_ascii_lowercase().to_string() + chars.as_str()
                    });
                    let value = camel_keys(value);
                    let keep_existing =
                        out.get(&camel).is_some_and(|existing| {
                            value.is_null()
                                || (!existing.is_null() && key != camel)
                        });
                    if !keep_existing {
                        out.insert(camel, value);
                    }
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(values) => serde_json::Value::Array(
                values.into_iter().map(camel_keys).collect(),
            ),
            value => value,
        }
    }

    Option::<serde_json::Value>::deserialize(deserializer)?
        .filter(|value| !value.is_null())
        .map(|value| serde_json::from_value(camel_keys(value)))
        .transpose()
        .map_err(serde::de::Error::custom)
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherCard {
    #[serde(rename = "CardholderName", alias = "cardholderName")]
    cardholder_name: Option<String>,
    #[serde(rename = "Number", alias = "number")]
    number: Option<String>,
    #[serde(rename = "Brand", alias = "brand")]
    brand: Option<String>,
    #[serde(rename = "ExpMonth", alias = "expMonth")]
    exp_month: Option<String>,
    #[serde(rename = "ExpYear", alias = "expYear")]
    exp_year: Option<String>,
    #[serde(rename = "Code", alias = "code")]
    code: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherIdentity {
    #[serde(rename = "Title", alias = "title")]
    title: Option<String>,
    #[serde(rename = "FirstName", alias = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "MiddleName", alias = "middleName")]
    middle_name: Option<String>,
    #[serde(rename = "LastName", alias = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "Address1", alias = "address1")]
    address1: Option<String>,
    #[serde(rename = "Address2", alias = "address2")]
    address2: Option<String>,
    #[serde(rename = "Address3", alias = "address3")]
    address3: Option<String>,
    #[serde(rename = "City", alias = "city")]
    city: Option<String>,
    #[serde(rename = "State", alias = "state")]
    state: Option<String>,
    #[serde(rename = "PostalCode", alias = "postalCode")]
    postal_code: Option<String>,
    #[serde(rename = "Country", alias = "country")]
    country: Option<String>,
    #[serde(rename = "Phone", alias = "phone")]
    phone: Option<String>,
    #[serde(rename = "Email", alias = "email")]
    email: Option<String>,
    #[serde(rename = "SSN", alias = "ssn")]
    ssn: Option<String>,
    #[serde(rename = "LicenseNumber", alias = "licenseNumber")]
    license_number: Option<String>,
    #[serde(rename = "PassportNumber", alias = "passportNumber")]
    passport_number: Option<String>,
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherSshKey {
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: Option<String>,
    #[serde(rename = "PublicKey", alias = "publicKey")]
    public_key: Option<String>,
    #[serde(rename = "Fingerprint", alias = "keyFingerprint")]
    fingerprint: Option<String>,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[repr(u16)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
    Linked = 3,
}

#[derive(
    serde_repr::Serialize_repr,
    serde_repr::Deserialize_repr,
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
)]
#[repr(u16)]
pub enum LinkedIdType {
    LoginUsername = 100,
    LoginPassword = 101,
    CardCardholderName = 300,
    CardExpMonth = 301,
    CardExpYear = 302,
    CardCode = 303,
    CardBrand = 304,
    CardNumber = 305,
    IdentityTitle = 400,
    IdentityMiddleName = 401,
    IdentityAddress1 = 402,
    IdentityAddress2 = 403,
    IdentityAddress3 = 404,
    IdentityCity = 405,
    IdentityState = 406,
    IdentityPostalCode = 407,
    IdentityCountry = 408,
    IdentityCompany = 409,
    IdentityEmail = 410,
    IdentityPhone = 411,
    IdentitySsn = 412,
    IdentityUsername = 413,
    IdentityPassportNumber = 414,
    IdentityLicenseNumber = 415,
    IdentityFirstName = 416,
    IdentityLastName = 417,
    IdentityFullName = 418,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherField {
    #[serde(rename = "Type", alias = "type")]
    ty: Option<FieldType>,
    #[serde(rename = "Name", alias = "name")]
    name: Option<String>,
    #[serde(rename = "Value", alias = "value")]
    value: Option<String>,
    #[serde(rename = "LinkedId", alias = "linkedId")]
    linked_id: Option<LinkedIdType>,
}

// this is just a name and some notes, both of which are already on the cipher
// object
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct CipherSecureNote {
    #[serde(rename = "type", default)]
    ty: u8,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
struct SyncResPasswordHistory {
    #[serde(rename = "LastUsedDate", alias = "lastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
}

fn encrypted_for(access_token: &str) -> Result<String> {
    use base64::Engine as _;

    #[derive(serde::Deserialize)]
    struct Claims {
        sub: String,
    }

    let invalid = || Error::UnsafeWrite {
        message: "access token lacks a usable subject; run bwu login --force"
            .into(),
    };
    let parts: Vec<_> = access_token.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(invalid());
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| invalid())?;
    let claims: Claims =
        serde_json::from_slice(&payload).map_err(|_| invalid())?;
    if claims.sub.trim().is_empty() {
        return Err(invalid());
    }
    Ok(claims.sub)
}

#[derive(serde::Serialize, Debug)]
struct CiphersPostReq {
    #[serde(rename = "encryptedFor")]
    encrypted_for: String,
    #[serde(rename = "type")]
    ty: u32, // XXX what are the valid types?
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    name: String,
    notes: Option<String>,
    login: Option<CipherLogin>,
    card: Option<CipherCard>,
    identity: Option<CipherIdentity>,
    #[serde(rename = "secureNote")]
    secure_note: Option<CipherSecureNote>,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersRes {
    #[serde(rename = "Data", alias = "data")]
    data: Vec<FoldersResData>,
}

#[derive(serde::Deserialize, Debug)]
struct FoldersResData {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(serde::Serialize, Debug)]
struct FoldersPostReq {
    name: String,
}

// Used for the Bitwarden-Client-Name header. Accepted values:
// https://github.com/bitwarden/server/blob/main/src/Core/Enums/BitwardenClient.cs
const BITWARDEN_CLIENT: &str = "cli";
// Protocol capability level; the actual CLI version remains in User-Agent.
// Vaultwarden omits SSH key ciphers for client capabilities before this version.
const BITWARDEN_CLIENT_VERSION: &str = "2024.12.0";

// DeviceType.LinuxDesktop, as per Bitwarden API device types.
const DEVICE_TYPE: u8 = 8;

#[derive(Debug)]
pub struct Client {
    base_url: String,
    identity_url: String,
    ui_url: String,
    client_cert_path: Option<std::path::PathBuf>,
}

impl Client {
    pub fn new(
        base_url: &str,
        identity_url: &str,
        ui_url: &str,
        client_cert_path: Option<&std::path::Path>,
    ) -> Self {
        Self {
            base_url: base_url.to_string(),
            identity_url: identity_url.to_string(),
            ui_url: ui_url.to_string(),
            client_cert_path: client_cert_path
                .map(std::path::Path::to_path_buf),
        }
    }

    /// Client identification for every request to the Bitwarden API. The
    /// server refuses to edit items with passkeys (and other newer data) for
    /// clients that do not report a recent enough version.
    fn bitwarden_headers() -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Bitwarden-Client-Name",
            reqwest::header::HeaderValue::from_static(BITWARDEN_CLIENT),
        );
        headers.insert(
            "Bitwarden-Client-Version",
            reqwest::header::HeaderValue::from_static(
                BITWARDEN_CLIENT_VERSION,
            ),
        );
        headers.append(
            "Device-Type",
            // unwrap is safe here because DEVICE_TYPE is a number and digits
            // are valid ASCII
            reqwest::header::HeaderValue::from_str(&DEVICE_TYPE.to_string())
                .unwrap(),
        );
        headers
    }

    fn user_agent() -> String {
        format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
    }

    /// Blocking client for Bitwarden API requests, identified like the async
    /// one.
    fn blocking_client() -> Result<reqwest::blocking::Client> {
        reqwest::blocking::Client::builder()
            .user_agent(Self::user_agent())
            .default_headers(Self::bitwarden_headers())
            .build()
            .map_err(|source| Error::CreateReqwestClient { source })
    }

    async fn reqwest_client(&self) -> Result<reqwest::Client> {
        let default_headers = Self::bitwarden_headers();
        let user_agent = Self::user_agent();
        if let Some(client_cert_path) = self.client_cert_path.as_ref() {
            let mut buf = Vec::new();
            let mut f = tokio::fs::File::open(client_cert_path)
                .await
                .map_err(|e| Error::LoadClientCert {
                    source: e,
                    file: client_cert_path.clone(),
                })?;
            f.read_to_end(&mut buf).await.map_err(|e| {
                Error::LoadClientCert {
                    source: e,
                    file: client_cert_path.clone(),
                }
            })?;
            let pem = reqwest::Identity::from_pem(&buf)
                .map_err(|e| Error::CreateReqwestClient { source: e })?;
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .identity(pem)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        } else {
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        }
    }

    /// Open the notifications websocket over the same HTTP client the api
    /// requests use, so proxies from the environment, the client certificate
    /// and the TLS roots all apply to it too.
    pub async fn notifications_websocket(
        &self,
        notifications_url: &str,
        access_token: &str,
    ) -> Result<reqwest::Upgraded> {
        use tokio_tungstenite::tungstenite::handshake::{
            client::generate_key, derive_accept_key,
        };

        // the token goes in both places: vaultwarden and the official server
        // read the query parameter, nodewarden only reads the header
        let url = format!(
            "{}/hub?access_token={access_token}",
            notifications_url.trim_end_matches('/')
        )
        .replacen("wss://", "https://", 1)
        .replacen("ws://", "http://", 1);
        let key = generate_key();
        let res = self
            .reqwest_client()
            .await?
            .get(url)
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {access_token}"),
            )
            .header(reqwest::header::CONNECTION, "Upgrade")
            .header(reqwest::header::UPGRADE, "websocket")
            .header(reqwest::header::SEC_WEBSOCKET_VERSION, "13")
            .header(reqwest::header::SEC_WEBSOCKET_KEY, &key)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        if res.status() != reqwest::StatusCode::SWITCHING_PROTOCOLS {
            return Err(Error::WebsocketHandshake {
                message: format!("server answered {}", res.status()),
            });
        }
        let header = |name: reqwest::header::HeaderName| {
            res.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        if !header(reqwest::header::UPGRADE).eq_ignore_ascii_case("websocket")
            || !header(reqwest::header::CONNECTION)
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
        {
            return Err(Error::WebsocketHandshake {
                message: "missing upgrade headers in the response"
                    .to_string(),
            });
        }
        if header(reqwest::header::SEC_WEBSOCKET_ACCEPT)
            != derive_accept_key(key.as_bytes())
        {
            return Err(Error::WebsocketHandshake {
                message: "wrong Sec-WebSocket-Accept in the response"
                    .to_string(),
            });
        }
        res.upgrade()
            .await
            .map_err(|source| Error::Reqwest { source })
    }

    pub async fn prelogin(
        &self,
        email: &str,
    ) -> Result<(KdfType, u32, Option<u32>, Option<u32>)> {
        let prelogin = PreloginReq {
            email: email.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/accounts/prelogin"))
            .json(&prelogin)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        let prelogin_res: PreloginRes = res.json_with_path().await?;
        Ok((
            prelogin_res.kdf,
            prelogin_res.kdf_iterations,
            prelogin_res.kdf_memory,
            prelogin_res.kdf_parallelism,
        ))
    }

    pub async fn register(
        &self,
        email: &str,
        device_id: &str,
        apikey: &crate::locked::ApiKey,
    ) -> Result<()> {
        let connect_req = ConnectTokenReq {
            auth: ConnectTokenAuth::ClientCredentials(
                ConnectTokenClientCredentials {
                    username: email.to_string(),
                    client_secret: String::from_utf8(
                        apikey.client_secret().to_vec(),
                    )
                    .unwrap(),
                },
            ),
            grant_type: "client_credentials".to_string(),
            scope: "api".to_string(),
            // XXX unwraps here are not necessarily safe
            client_id: String::from_utf8(apikey.client_id().to_vec())
                .unwrap(),
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id.to_string(),
            device_name: "rbw".to_string(),
            device_push_token: String::new(),
            two_factor_token: None,
            two_factor_provider: None,
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    pub async fn login(
        &self,
        email: &str,
        sso_id: Option<&str>,
        device_id: &str,
        password_hash: &crate::locked::PasswordHash,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<TwoFactorProviderType>,
    ) -> Result<(String, String, String)> {
        let connect_req = match sso_id {
            Some(sso_id) => {
                let (sso_code, sso_code_verifier, callback_url) =
                    self.obtain_sso_code(sso_id).await?;

                ConnectTokenReq {
                    auth: ConnectTokenAuth::AuthCode(ConnectTokenAuthCode {
                        code: sso_code,
                        code_verifier: sso_code_verifier,
                        redirect_uri: callback_url,
                    }),
                    grant_type: "authorization_code".to_string(),
                    scope: "api offline_access".to_string(),
                    client_id: "cli".to_string(),
                    device_type: u32::from(DEVICE_TYPE),
                    device_identifier: device_id.to_string(),
                    device_name: "rbw".to_string(),
                    device_push_token: String::new(),
                    two_factor_token: two_factor_token
                        .map(std::string::ToString::to_string),
                    two_factor_provider: two_factor_provider
                        .map(|ty| ty as u32),
                }
            }
            None => ConnectTokenReq {
                auth: ConnectTokenAuth::Password(ConnectTokenPassword {
                    username: email.to_string(),
                    password: crate::base64::encode(password_hash.hash()),
                }),

                grant_type: "password".to_string(),
                scope: "api offline_access".to_string(),
                client_id: "cli".to_string(),
                device_type: 8,
                device_identifier: device_id.to_string(),
                device_name: "rbw".to_string(),
                device_push_token: String::new(),
                two_factor_token: two_factor_token
                    .map(std::string::ToString::to_string),
                two_factor_provider: two_factor_provider.map(|ty| ty as u32),
            },
        };

        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .header(
                "auth-email",
                crate::base64::encode_url_safe_no_pad(email),
            )
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;

        if res.status() == reqwest::StatusCode::OK {
            let connect_res: ConnectTokenRes = res.json_with_path().await?;
            Ok((
                connect_res.access_token,
                connect_res.refresh_token,
                connect_res.key,
            ))
        } else {
            let code = res.status().as_u16();
            match res.text().await {
                Ok(body) => match body.clone().json_with_path() {
                    Ok(json) => Err(classify_login_error(&json, code)),
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed { status: code })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed { status: code })
                }
            }
        }
    }

    pub async fn send_email_login(
        &self,
        email: &str,
        device_id: &str,
        sso_email_2fa_session_token: &str,
    ) -> Result<()> {
        let send_email_login_req = SendEmailLoginReq {
            email: email.to_string(),
            device_identifier: device_id.to_string(),
            sso_email_2fa_session_token: sso_email_2fa_session_token
                .to_string(),
        };

        let client = self.reqwest_client().await?;
        let res = client
            .post(self.api_url("/two-factor/send-email-login"))
            .json(&send_email_login_req)
            .header(
                "auth-email",
                crate::base64::encode_url_safe_no_pad(email),
            )
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;

        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            log::warn!("{code}: {:?}", res.text().await);
            Err(Error::RequestFailed { status: code })
        }
    }

    async fn obtain_sso_code(
        &self,
        sso_id: &str,
    ) -> Result<(String, String, String)> {
        let state =
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);
        let sso_code_verifier =
            rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);

        let mut hasher = sha2::Sha256::new();
        hasher.update(sso_code_verifier.clone());
        let code_challenge =
            crate::base64::encode_url_safe_no_pad(hasher.finalize());

        let port = find_free_port(8065, 8070).await?;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| Error::CreateSSOCallbackServer { err: e })?;

        let callback_server =
            start_sso_callback_server(listener, state.as_str());

        let callback_url =
            "http://localhost:".to_string() + port.to_string().as_str();

        open::that(
            self.ui_url.clone()
                + "/#/sso?clientId="
                + "cli"
                + "&redirectUri="
                + urlencoding::encode(callback_url.as_str())
                    .into_owned()
                    .as_str()
                + "&state="
                + state.as_str()
                + "&codeChallenge="
                + code_challenge.as_str()
                + "&identifier="
                + sso_id,
        )
        .map_err(|e| Error::FailedToOpenWebBrowser { err: e })?;
        // TODO: probably it'd be better to display the URL in the console if the automatic
        // open operation fails, instead of failing the whole process? E.g. docker container
        // case

        let sso_code = callback_server.await?;

        Ok((sso_code, sso_code_verifier, callback_url))
    }

    pub async fn sync(
        &self,
        access_token: &str,
    ) -> Result<(
        String,
        String,
        std::collections::HashMap<String, String>,
        Vec<crate::db::Entry>,
    )> {
        let client = self.reqwest_client().await?;
        let res = client
            .get(self.api_url("/sync"))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let sync_res: SyncRes = res.json_with_path().await?;
                let folders = sync_res.folders.clone();
                let ciphers = sync_res
                    .ciphers
                    .iter()
                    .filter_map(|cipher| cipher.to_entry(&folders))
                    .collect();
                let org_keys = sync_res
                    .profile
                    .organizations
                    .iter()
                    .map(|org| (org.id.clone(), org.key.clone()))
                    .collect();
                Ok((
                    sync_res.profile.key,
                    sync_res.profile.private_key,
                    org_keys,
                    ciphers,
                ))
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn add(
        &self,
        access_token: &str,
        name: &str,
        data: &crate::db::EntryData,
        notes: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<()> {
        let mut req = CiphersPostReq {
            encrypted_for: encrypted_for(access_token)?,
            ty: 1,
            folder_id: folder_id.map(std::string::ToString::to_string),
            name: name.to_string(),
            notes: notes.map(std::string::ToString::to_string),
            login: None,
            card: None,
            identity: None,
            secure_note: None,
        };
        match data {
            crate::db::EntryData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                let uris = if uris.is_empty() {
                    None
                } else {
                    Some(
                        uris.iter()
                            .map(|s| CipherLoginUri {
                                uri: Some(s.uri.clone()),
                                match_type: s.match_type,
                            })
                            .collect(),
                    )
                };
                req.login = Some(CipherLogin {
                    username: username.clone(),
                    password: password.clone(),
                    totp: totp.clone(),
                    uris,
                    fido2_credentials: None,
                });
            }
            crate::db::EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => {
                req.ty = 3;
                req.card = Some(CipherCard {
                    cardholder_name: cardholder_name.clone(),
                    number: number.clone(),
                    brand: brand.clone(),
                    exp_month: exp_month.clone(),
                    exp_year: exp_year.clone(),
                    code: code.clone(),
                });
            }
            crate::db::EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                address1,
                address2,
                address3,
                city,
                state,
                postal_code,
                country,
                phone,
                email,
                ssn,
                license_number,
                passport_number,
                username,
            } => {
                req.ty = 4;
                req.identity = Some(CipherIdentity {
                    title: title.clone(),
                    first_name: first_name.clone(),
                    middle_name: middle_name.clone(),
                    last_name: last_name.clone(),
                    address1: address1.clone(),
                    address2: address2.clone(),
                    address3: address3.clone(),
                    city: city.clone(),
                    state: state.clone(),
                    postal_code: postal_code.clone(),
                    country: country.clone(),
                    phone: phone.clone(),
                    email: email.clone(),
                    ssn: ssn.clone(),
                    license_number: license_number.clone(),
                    passport_number: passport_number.clone(),
                    username: username.clone(),
                });
            }
            crate::db::EntryData::SecureNote => {
                req.ty = 2;
                req.secure_note = Some(CipherSecureNote { ty: 0 });
            }
            crate::db::EntryData::SshKey { .. } => unreachable!(),
        }
        let client = Self::blocking_client()?;
        let res = client
            .post(self.api_url("/ciphers"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    fn transfer_client(&self) -> Result<reqwest::blocking::Client> {
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .connect_timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &self.client_cert_path {
            let bytes =
                zeroize::Zeroizing::new(std::fs::read(path).map_err(
                    |source| Error::LoadClientCert {
                        source,
                        file: path.clone(),
                    },
                )?);
            builder = builder.identity(
                reqwest::Identity::from_pem(&bytes).map_err(|source| {
                    Error::CreateReqwestClient { source }
                })?,
            );
        }
        builder
            .build()
            .map_err(|source| Error::CreateReqwestClient { source })
    }

    /// Only encrypted item data may be passed to this method.
    pub fn cipher_request(
        &self,
        token: &str,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let create_body = if method == reqwest::Method::POST
            && path == "/ciphers"
        {
            let subject = encrypted_for(token)?;
            let mut cipher = body
                .cloned()
                .filter(serde_json::Value::is_object)
                .ok_or_else(|| Error::UnsafeWrite {
                    message: "cipher creation requires an object body".into(),
                })?;
            cipher["encryptedFor"] = serde_json::Value::String(subject);
            Some(cipher)
        } else {
            None
        };
        let body = create_body.as_ref().or(body);
        let client = self.transfer_client()?;
        let mut request = client
            .request(method, self.api_url(path))
            .headers(Self::bitwarden_headers())
            .bearer_auth(token);
        if let Some(body) = body {
            request = request.json(body);
        }
        let response =
            request.send().map_err(|source| Error::Reqwest { source })?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::RequestUnauthorized);
        }
        if !response.status().is_success() {
            return Err(Error::RequestFailed {
                status: response.status().as_u16(),
            });
        }
        response.json().map_err(|source| Error::Reqwest { source })
    }

    pub fn attachment_upload(
        &self,
        token: &str,
        item: &str,
        filename: &str,
        key: &str,
        encrypted: &[u8],
    ) -> Result<String> {
        let created = self.cipher_request(token, reqwest::Method::POST, &format!("/ciphers/{item}/attachment/v2"), Some(&serde_json::json!({"fileName":filename,"key":key,"fileSize":encrypted.len()})))?;
        let id = created["attachmentId"]
            .as_str()
            .filter(|id| {
                !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            .ok_or_else(|| Error::UnsafeWrite {
                message: "invalid attachment id from server".into(),
            })?;
        let client = self.transfer_client()?;
        let response = if created["fileUploadType"].as_u64() == Some(0) {
            // Use our configured API origin; never forward bearer tokens to an upload URL.
            client.post(self.api_url(&format!("/ciphers/{item}/attachment/{id}")))
                .headers(Self::bitwarden_headers())
                .bearer_auth(token)
                .multipart(reqwest::blocking::multipart::Form::new().part("data", reqwest::blocking::multipart::Part::bytes(encrypted.to_vec()).file_name(filename.to_owned()).mime_str("application/octet-stream").map_err(|_| Error::UnsafeWrite { message: "invalid attachment content type".into() })?))
                .send()
        } else if created["fileUploadType"].as_u64() == Some(1) {
            let url = checked_download_url(created["url"].as_str().unwrap_or(""), &self.api_url(""))?;
            client.put(url).header("x-ms-blob-type", "BlockBlob").header("Content-Type", "application/octet-stream").body(encrypted.to_vec()).send()
        } else { return Err(Error::UnsafeWrite { message: "unsupported attachment upload type; metadata may already exist, inspect before retrying".into() }); }
        .map_err(|_| Error::UnsafeWrite { message: "attachment upload failed; metadata may already exist, inspect before retrying".into() })?;
        if !response.status().is_success() {
            return Err(Error::RequestFailed {
                status: response.status().as_u16(),
            });
        }
        Ok(id.to_owned())
    }

    pub fn attachment_download(
        &self,
        token: &str,
        item: &str,
        attachment: &str,
        limit: u64,
    ) -> Result<(serde_json::Value, Vec<u8>)> {
        use std::io::Read as _;
        let metadata = self.cipher_request(
            token,
            reqwest::Method::GET,
            &format!("/ciphers/{item}/attachment/{attachment}"),
            None,
        )?;
        let url = checked_download_url(
            metadata["url"].as_str().unwrap_or(""),
            &self.api_url(""),
        )?;
        // Signed URLs carry their own authorization. No vault token or client certificate.
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(180))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|source| Error::CreateReqwestClient { source })?;
        let response =
            client.get(url).send().map_err(|_| Error::UnsafeWrite {
                message: "attachment download failed".into(),
            })?;
        if !response.status().is_success() {
            return Err(Error::RequestFailed {
                status: response.status().as_u16(),
            });
        }
        if response.content_length().is_some_and(|size| size > limit) {
            return Err(Error::UnsafeWrite {
                message: "attachment exceeds size limit".into(),
            });
        }
        let mut bytes = Vec::new();
        response
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::UnsafeWrite {
                message: "failed to read encrypted attachment".into(),
            })?;
        if bytes.len() as u64 > limit {
            return Err(Error::UnsafeWrite {
                message: "attachment exceeds size limit".into(),
            });
        }
        Ok((metadata, bytes))
    }

    /// Preserve server-only metadata and reject stale edits before PUT.
    pub fn patch_cipher(
        &self,
        access_token: &str,
        id: &str,
        patch: &crate::mutation::Patch,
    ) -> Result<()> {
        let subject = encrypted_for(access_token)?;
        let mut builder = reqwest::blocking::Client::builder()
            .user_agent(Self::user_agent())
            .default_headers(Self::bitwarden_headers())
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10));
        if let Some(path) = &self.client_cert_path {
            let bytes =
                zeroize::Zeroizing::new(std::fs::read(path).map_err(
                    |source| Error::LoadClientCert {
                        source,
                        file: path.clone(),
                    },
                )?);
            let identity = reqwest::Identity::from_pem(&bytes)
                .map_err(|source| Error::CreateReqwestClient { source })?;
            builder = builder.identity(identity);
        }
        let client = builder
            .build()
            .map_err(|source| Error::CreateReqwestClient { source })?;
        let endpoint = self.api_url(&format!("/ciphers/{id}"));
        let response = client
            .get(&endpoint)
            .bearer_auth(access_token)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(Error::RequestUnauthorized);
        }
        if !response.status().is_success() {
            return Err(Error::RequestFailed {
                status: response.status().as_u16(),
            });
        }
        let mut cipher: serde_json::Value = response
            .json()
            .map_err(|source| Error::Reqwest { source })?;
        patch.apply(&mut cipher)?;
        cipher["encryptedFor"] = serde_json::Value::String(subject);
        let response = client
            .put(endpoint)
            .bearer_auth(access_token)
            .json(&cipher)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match response.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            status => Err(Error::RequestFailed {
                status: status.as_u16(),
            }),
        }
    }

    pub fn remove(&self, access_token: &str, id: &str) -> Result<()> {
        let client = Self::blocking_client()?;
        let res = client
            .delete(self.api_url(&format!("/ciphers/{id}")))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => Ok(()),
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn folders(
        &self,
        access_token: &str,
    ) -> Result<Vec<(String, String)>> {
        let client = Self::blocking_client()?;
        let res = client
            .get(self.api_url("/folders"))
            .header("Authorization", format!("Bearer {access_token}"))
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let folders_res: FoldersRes = res.json_with_path()?;
                Ok(folders_res
                    .data
                    .iter()
                    .map(|folder| (folder.id.clone(), folder.name.clone()))
                    .collect())
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn create_folder(
        &self,
        access_token: &str,
        name: &str,
    ) -> Result<String> {
        let req = FoldersPostReq {
            name: name.to_string(),
        };
        let client = Self::blocking_client()?;
        let res = client
            .post(self.api_url("/folders"))
            .header("Authorization", format!("Bearer {access_token}"))
            .json(&req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        match res.status() {
            reqwest::StatusCode::OK => {
                let folders_res: FoldersResData = res.json_with_path()?;
                Ok(folders_res.id)
            }
            reqwest::StatusCode::UNAUTHORIZED => {
                Err(Error::RequestUnauthorized)
            }
            _ => Err(Error::RequestFailed {
                status: res.status().as_u16(),
            }),
        }
    }

    pub fn exchange_refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "cli".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = Self::blocking_client()?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .map_err(|source| Error::Reqwest { source })?;
        if res.status() != reqwest::StatusCode::OK {
            let code = res.status().as_u16();
            return Err(refresh_error(code, &res.text().unwrap_or_default()));
        }
        let connect_res: ConnectRefreshTokenRes = res.json_with_path()?;
        Ok(connect_res.access_token)
    }

    pub async fn exchange_refresh_token_async(
        &self,
        refresh_token: &str,
    ) -> Result<String> {
        let connect_req = ConnectRefreshTokenReq {
            grant_type: "refresh_token".to_string(),
            client_id: "cli".to_string(),
            refresh_token: refresh_token.to_string(),
        };
        let client = self.reqwest_client().await?;
        let res = client
            .post(self.identity_url("/connect/token"))
            .form(&connect_req)
            .send()
            .await
            .map_err(|source| Error::Reqwest { source })?;
        if res.status() != reqwest::StatusCode::OK {
            let code = res.status().as_u16();
            let body = res.text().await.unwrap_or_default();
            return Err(refresh_error(code, &body));
        }
        let connect_res: ConnectRefreshTokenRes =
            res.json_with_path().await?;
        Ok(connect_res.access_token)
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}

#[derive(serde::Deserialize, Debug)]
struct OAuthErrorRes {
    error: String,
    error_description: Option<String>,
}

// The token endpoint answers a failed refresh with an OAuth error body such
// as `{"error":"invalid_grant"}`, which must not be parsed as a token.
fn refresh_error(status: u16, body: &str) -> Error {
    if let Ok(res) = serde_json::from_str::<OAuthErrorRes>(body) {
        Error::RefreshTokenRejected {
            error: res.error,
            description: res.error_description.filter(|d| !d.is_empty()),
        }
    } else {
        log::warn!("refresh token exchange failed ({status}): {body}");
        Error::RequestFailed { status }
    }
}

async fn find_free_port(bottom: u16, top: u16) -> Result<u16> {
    for port in bottom..top {
        if tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }

    Err(Error::FailedToFindFreePort {
        range: format!("({bottom}..{top})"),
    })
}

#[derive(Clone)]
struct SSOHandlerState {
    state: String,
    sender: tokio::sync::mpsc::Sender<Result<String>>,
}

async fn start_sso_callback_server(
    listener: tokio::net::TcpListener,
    state: &str,
) -> Result<String> {
    let (shut_sender, shut_receiver) = tokio::sync::mpsc::channel(1);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

    let sso_handler_state = std::sync::Arc::new(SSOHandlerState {
        state: state.to_string(),
        sender: shut_sender,
    });

    let app = axum::Router::new()
        .route("/", axum::routing::get(handle_sso_callback))
        .with_state(sso_handler_state);

    axum::serve(listener, app)
        .with_graceful_shutdown(sso_server_graceful_shutdown(
            sender,
            shut_receiver,
        ))
        .await
        .map_err(|e| Error::FailedToProcessSSOCallback {
            msg: e.to_string(),
        })?;

    receiver.recv().await.unwrap()
}

async fn sso_server_graceful_shutdown(
    sender: tokio::sync::mpsc::Sender<Result<String>>,
    mut receiver: tokio::sync::mpsc::Receiver<Result<String>>,
) {
    sender.send(receiver.recv().await.unwrap()).await.unwrap();
}

async fn handle_sso_callback(
    axum::extract::State(state): axum::extract::State<
        std::sync::Arc<SSOHandlerState>,
    >,
    axum::extract::Query(params): axum::extract::Query<
        std::collections::HashMap<String, String>,
    >,
) -> axum::http::Response<String> {
    match sso_query_code(&params, state.state.as_str()) {
        Ok(sso_code) => {
            state.sender.send(Ok(sso_code)).await.unwrap();

            axum::http::Response::builder().status(axum::http::StatusCode::OK).
            body(
                "<html><head><title>Success | rbw</title></head><body> \
                  <h1>Successfully authenticated with rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>".to_string()).unwrap()
        }
        Err(e) => {
            state.sender.send(Err(e)).await.unwrap();

            axum::http::Response::builder().status(axum::http::StatusCode::BAD_REQUEST).
            body(
                "<html><head><title>Failed | rbw</title></head><body> \
                  <h1>Something went wrong logging into the rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>".to_string()).unwrap()
        }
    }
}

fn sso_query_code(
    params: &std::collections::HashMap<String, String>,
    state: &str,
) -> Result<String> {
    let sso_code =
        params
            .get("code")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain code from the URL".to_string(),
            })?;

    let received_state =
        params
            .get("state")
            .ok_or(Error::FailedToProcessSSOCallback {
                msg: "Could not obtain state from the URL".to_string(),
            })?;

    if received_state.split("_identifier=").next().unwrap() != state {
        return Err(Error::FailedToProcessSSOCallback {
            msg: format!("SSO callback states do not match, sent: {state}, received: {received_state}"),
        });
    }

    Ok(sso_code.clone())
}

fn classify_login_error(error_res: &ConnectErrorRes, code: u16) -> Error {
    let error_desc = error_res.error_description.clone();
    let error_desc = error_desc.as_deref();
    match error_res.error.as_str() {
        "invalid_grant" => match error_desc {
            Some("invalid_username_or_password") => {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    return Error::IncorrectPassword { message };
                }
            }
            Some("Two factor required.") => {
                if let Some(providers) =
                    error_res.two_factor_providers.as_ref()
                {
                    return Error::TwoFactorRequired {
                        providers: providers.clone(),
                        sso_email_2fa_session_token: error_res
                            .sso_email_2fa_session_token
                            .clone(),
                    };
                }
            }
            Some("Captcha required.") => {
                return Error::RegistrationRequired;
            }
            _ => {}
        },
        "invalid_client" => {
            return Error::IncorrectApiKey;
        }
        "" => {
            // bitwarden_rs returns an empty error and error_description for
            // this case, for some reason
            if error_desc.is_none() || error_desc == Some("") {
                if let Some(error_model) = error_res.error_model.as_ref() {
                    let message = error_model.message.as_str().to_string();
                    match message.as_str() {
                        "Username or password is incorrect. Try again"
                        | "TOTP code is not a number" => {
                            return Error::IncorrectPassword { message };
                        }
                        s => {
                            if s.starts_with(
                                "Invalid TOTP code! Server time: ",
                            ) {
                                return Error::IncorrectPassword { message };
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    log::warn!("unexpected error received during login: {error_res:?}");
    Error::RequestFailed { status: code }
}

#[cfg(test)]
fn assert_api_identification(
    headers: &std::collections::HashMap<String, String>,
) {
    assert_eq!(
        headers.get("bitwarden-client-name").map(String::as_str),
        Some(BITWARDEN_CLIENT)
    );
    assert_eq!(
        headers.get("bitwarden-client-version").map(String::as_str),
        Some(BITWARDEN_CLIENT_VERSION)
    );
    assert_eq!(headers.get("device-type"), Some(&DEVICE_TYPE.to_string()));
}

#[cfg(test)]
mod patch_tests {
    use super::*;
    use std::io::{BufRead as _, Read as _, Write as _};

    #[test]
    fn patch_transport_preserves_cipher_and_sends_revision() {
        check_patch_transport(false);
    }

    #[test]
    fn folder_move_transport_preserves_secrets_and_attachments() {
        check_patch_transport(true);
    }

    fn token(subject: &str) -> String {
        use base64::Engine as _;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(
                serde_json::json!({"sub": subject, "exp": 0}).to_string(),
            );
        format!("header.{payload}.signature")
    }

    #[test]
    fn create_transport_sets_encrypted_for_from_each_token() {
        for subject in ["user-one", "user-two"] {
            check_create_transport(subject, false);
        }
    }

    #[test]
    fn native_create_transport_sets_encrypted_for_from_each_token() {
        for subject in ["user-one", "user-two"] {
            check_create_transport(subject, true);
        }
    }

    #[test]
    fn attachment_transport_leaves_body_unchanged() {
        check_create_transport("fixture-token", false);
    }

    #[test]
    fn malformed_token_rejects_writes_before_network() {
        let client = Client::new("http://127.0.0.1:1", "", "", None);
        let body = serde_json::json!({"name":"encrypted-name"});
        for result in [
            client.add(
                "private-token-sentinel",
                "name",
                &crate::db::EntryData::SecureNote,
                None,
                None,
            ),
            client.patch_cipher(
                "private-token-sentinel",
                "fixture",
                &crate::mutation::Patch::default(),
            ),
            client
                .cipher_request(
                    "private-token-sentinel",
                    reqwest::Method::POST,
                    "/ciphers",
                    Some(&body),
                )
                .map(|_| ()),
        ] {
            let error = result.unwrap_err();
            assert!(matches!(error, Error::UnsafeWrite { .. }));
            assert!(error.to_string().contains("bwu login --force"));
            assert!(!format!("{error:?} {error}")
                .contains("private-token-sentinel"));
        }
    }

    #[test]
    fn token_subject_rejects_malformed_claims_without_exposing_values() {
        use base64::Engine as _;
        let encode = |payload: &str| {
            let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(payload);
            format!("header.{payload}.signature")
        };
        let mut tokens: Vec<String> = [
            "",
            "private-token-sentinel",
            "one.two",
            "one.two.three.four",
            ".e30.signature",
            "header..signature",
            "header.e30.",
            "header.!.signature",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        for payload in [
            "private-claim-sentinel",
            "{}",
            r#"{"sub":null}"#,
            r#"{"sub":42,"private":"private-claim-sentinel"}"#,
            r#"{"sub":""}"#,
            r#"{"sub":"  \t"}"#,
        ] {
            tokens.push(encode(payload));
        }
        for token in tokens {
            let error = encrypted_for(&token).unwrap_err();
            assert!(matches!(error, Error::UnsafeWrite { .. }));
            assert!(error.to_string().contains("bwu login --force"));
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("private-token-sentinel"));
            assert!(!rendered.contains("private-claim-sentinel"));
            if !token.is_empty() {
                assert!(!rendered.contains(&token));
            }
        }
        assert_eq!(encrypted_for(&token("user-one")).unwrap(), "user-one");
        assert_eq!(
            encrypted_for(&token(" user-two ")).unwrap(),
            " user-two "
        );
    }

    #[test]
    fn native_create_requires_an_object_body() {
        let client = Client::new("http://127.0.0.1:1", "", "", None);
        for body in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!([])),
            Some(serde_json::json!("cipher")),
        ] {
            let error = client
                .cipher_request(
                    &token("user-one"),
                    reqwest::Method::POST,
                    "/ciphers",
                    body.as_ref(),
                )
                .unwrap_err();
            assert!(matches!(error, Error::UnsafeWrite { .. }));
            assert!(error.to_string().contains("object body"));
        }
    }

    fn check_create_transport(subject: &str, native: bool) {
        let attachment = subject == "fixture-token";
        let token = if attachment {
            subject.into()
        } else {
            token(subject)
        };
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = if attachment {
            serde_json::json!({"fileName":"encrypted-name", "key":"encrypted-key", "fileSize":42})
        } else {
            serde_json::json!({"name":"encrypted-name", "organizationId":"org", "encryptedFor":"stale", "encryptedByKeyId":"key-id"})
        };
        let borrowed_body = body.clone();
        let original = body.clone();
        let expected_token = token.clone();
        let subject = subject.to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut reader =
                std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let path = if attachment {
                "/ciphers/fixture/attachment/v2"
            } else {
                "/ciphers"
            };
            assert!(line.starts_with(&format!("POST {path} ")));
            let mut len = 0;
            let mut authorization = String::new();
            let mut headers = std::collections::HashMap::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.insert(
                        name.to_ascii_lowercase(),
                        value.trim().to_owned(),
                    );
                }
                if let Some(value) =
                    line.to_ascii_lowercase().strip_prefix("content-length:")
                {
                    len = value.trim().parse::<usize>().unwrap();
                }
                if line.to_ascii_lowercase().starts_with("authorization:") {
                    authorization = line.trim().to_string();
                }
            }
            assert_api_identification(&headers);
            assert_eq!(
                authorization,
                format!("authorization: Bearer {expected_token}")
            );
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes).unwrap();
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap();
            if attachment {
                assert_eq!(value, original);
                assert!(value.get("encryptedFor").is_none());
            } else {
                assert_eq!(value["name"], "encrypted-name");
                assert_eq!(value["encryptedFor"], subject);
                if native {
                    assert_eq!(value["organizationId"], "org");
                    assert_eq!(value["encryptedByKeyId"], "key-id");
                } else {
                    assert_eq!(value["type"], 2);
                    assert_eq!(value["notes"], "encrypted-notes");
                    assert_eq!(value["folderId"], "folder");
                }
            }
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").unwrap();
        });
        let client = Client::new(&format!("http://{address}"), "", "", None);
        let result = if native || attachment {
            client
                .cipher_request(
                    &token,
                    reqwest::Method::POST,
                    if attachment {
                        "/ciphers/fixture/attachment/v2"
                    } else {
                        "/ciphers"
                    },
                    Some(&body),
                )
                .map(|_| ())
        } else {
            client.add(
                &token,
                "encrypted-name",
                &crate::db::EntryData::SecureNote,
                Some("encrypted-notes"),
                Some("folder"),
            )
        };
        let server_result = server.join();
        assert_eq!(body, borrowed_body);
        server_result.unwrap();
        result.unwrap();
    }

    fn check_patch_transport(move_folder: bool) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut original = serde_json::json!({"id":"fixture", "folderId":"old-folder", "revisionDate":"2026-09-06T00:00:00Z", "favorite":true,
                "reprompt":1, "key":null, "login":{"password":"encrypted-old", "fido2Credentials":[{"keyValue":"encrypted-passkey"}]},
                "attachments":[{"id":"attachment","fileName":"encrypted-name","key":"encrypted-key"}]});
            original["encryptedByKeyId"] = serde_json::Value::Null;
            original["serverMetadata"] = serde_json::json!({"unknown": true});
            // The server's copy of the typed fields; it wins over them on PUT.
            original["data"] = serde_json::Value::String(
                serde_json::json!({"password":"encrypted-old"}).to_string(),
            );
            if move_folder {
                original["encryptedFor"] = serde_json::json!("stale");
            }
            for method in ["GET", "PUT"] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(
                        10,
                    )))
                    .unwrap();
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(
                    line.starts_with(&format!("{method} /ciphers/fixture "))
                );
                let mut len = 0;
                let mut headers = std::collections::HashMap::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:")
                    {
                        len = value.trim().parse::<usize>().unwrap();
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        headers.insert(
                            name.to_ascii_lowercase(),
                            value.trim().to_owned(),
                        );
                    }
                }
                // Without it the server refuses to edit items with passkeys.
                assert_api_identification(&headers);
                let mut body = vec![0; len];
                reader.read_exact(&mut body).unwrap();
                if method == "PUT" {
                    let value: serde_json::Value =
                        serde_json::from_slice(&body).unwrap();
                    assert_eq!(
                        value["login"]["password"],
                        if move_folder {
                            "encrypted-old"
                        } else {
                            "encrypted-new"
                        }
                    );
                    assert_eq!(
                        value["folderId"],
                        if move_folder {
                            "new-folder"
                        } else {
                            "old-folder"
                        }
                    );
                    assert_eq!(
                        value["login"]["fido2Credentials"],
                        original["login"]["fido2Credentials"]
                    );
                    assert_eq!(value["encryptedFor"], "patch-user");
                    assert_eq!(
                        value["encryptedByKeyId"],
                        serde_json::Value::Null
                    );
                    assert_eq!(value["serverMetadata"]["unknown"], true);
                    assert!(value.get("data").is_none());
                    assert_eq!(value["favorite"], true);
                    assert_eq!(value["reprompt"], 1);
                    assert_eq!(
                        value["lastKnownRevisionDate"],
                        original["revisionDate"]
                    );
                    assert_eq!(
                        value["attachments2"]["attachment"]["key"],
                        "encrypted-key"
                    );
                }
                let body = if method == "GET" {
                    original.to_string()
                } else {
                    "{}".into()
                };
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
            }
        });
        let client = Client::new(&format!("http://{address}"), "", "", None);
        let mut patch = crate::mutation::Patch::default();
        if move_folder {
            patch.change(
                "/folderId",
                serde_json::json!("old-folder"),
                serde_json::json!("new-folder"),
            );
        } else {
            patch.change(
                "/login/password",
                serde_json::json!("encrypted-old"),
                serde_json::json!("encrypted-new"),
            );
        }
        client
            .patch_cipher(&token("patch-user"), "fixture", &patch)
            .unwrap();
        server.join().unwrap();
    }
}

#[cfg(test)]
mod refresh_tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn refresh_rejection_is_reported_not_parsed_as_token() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let _ = stream.read(&mut buf).unwrap();
            // Vaultwarden's body for a revoked refresh token.
            let body = r#"{"error":"invalid_grant"}"#;
            write!(stream, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let client = Client::new("", &format!("http://{address}"), "", None);
        let err = client.exchange_refresh_token("revoked").unwrap_err();
        server.join().unwrap();
        assert!(
            matches!(&err, Error::RefreshTokenRejected { error, description: None } if error == "invalid_grant"),
            "{err:?}"
        );
        assert!(err.to_string().contains("bwu login --force"));
    }

    #[test]
    fn refresh_error_keeps_description_and_falls_back_on_non_oauth_body() {
        let err = refresh_error(
            400,
            r#"{"error":"invalid_grant","error_description":"expired"}"#,
        );
        assert!(err.to_string().contains("(invalid_grant: expired)"));
        assert!(matches!(
            refresh_error(502, "<html>bad gateway</html>"),
            Error::RequestFailed { status: 502 }
        ));
    }
}

#[cfg(test)]
mod compat_tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(default, deserialize_with = "deserialize_login")]
        login: Option<CipherLogin>,
    }

    #[test]
    fn login_is_written_in_camel_case() {
        let login = CipherLogin {
            username: Some("u".to_string()),
            password: Some("p".to_string()),
            totp: None,
            uris: Some(vec![CipherLoginUri {
                uri: Some("https://example.invalid".to_string()),
                match_type: None,
            }]),
            fido2_credentials: None,
        };
        let json = serde_json::to_value(&login).unwrap();
        let mut keys: Vec<_> = json.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["password", "totp", "uris", "username"]);
        let uri = &json["uris"][0];
        assert!(uri.get("uri").is_some() && uri.get("match").is_some());
    }

    #[test]
    fn login_with_both_cases_of_a_field_still_parses() {
        // what nodewarden stores for a login written in PascalCase
        let w: Wrapper = serde_json::from_str(
            r#"{"login":{"Username":"old-u","Password":"p","Totp":null,
                "Uris":[{"Uri":"old","Match":null}],"fido2Credentials":null,
                "uris":[{"uri":"new","match":null}],"username":null}}"#,
        )
        .unwrap();
        let login = w.login.unwrap();
        assert_eq!(login.username.as_deref(), Some("old-u"));
        assert_eq!(login.password.as_deref(), Some("p"));
        let uris = login.uris.unwrap();
        assert_eq!(uris.len(), 1);
        assert_eq!(uris[0].uri.as_deref(), Some("new"));

        let w: Wrapper = serde_json::from_str(r#"{"login":null}"#).unwrap();
        assert!(w.login.is_none());
        let w: Wrapper = serde_json::from_str("{}").unwrap();
        assert!(w.login.is_none());
    }

    fn serve_once(
        respond: impl FnOnce(&str) -> String + Send + 'static,
    ) -> (String, std::thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            stream.write_all(respond(&request).as_bytes()).unwrap();
            request
        });
        (format!("http://{address}/notifications"), server)
    }

    fn request_key(request: &str) -> String {
        request
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .starts_with("sec-websocket-key:")
                    .then(|| l.split_once(':').unwrap().1.trim().to_string())
            })
            .unwrap()
    }

    #[tokio::test]
    async fn notifications_handshake_sends_token_in_header_and_query() {
        let (url, server) = serve_once(|request| {
            let accept =
                tokio_tungstenite::tungstenite::handshake::derive_accept_key(
                    request_key(request).as_bytes(),
                );
            format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n")
        });
        let client = Client::new("", "", "", None);
        client
            .notifications_websocket(&url, "fixture-token")
            .await
            .unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with(
            "GET /notifications/hub?access_token=fixture-token HTTP/1.1"
        ));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token\r\n"));
    }

    #[tokio::test]
    async fn notifications_handshake_rejects_wrong_accept_key() {
        let (url, server) = serve_once(|_| {
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: bogus\r\n\r\n".to_string()
        });
        let client = Client::new("", "", "", None);
        let err = client
            .notifications_websocket(&url, "fixture-token")
            .await
            .unwrap_err();
        server.join().unwrap();
        assert!(err.to_string().contains("Sec-WebSocket-Accept"), "{err}");
    }

    #[tokio::test]
    async fn notifications_handshake_reports_rejected_token() {
        let (url, server) = serve_once(|_| {
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
                .to_string()
        });
        let client = Client::new("", "", "", None);
        let err = client
            .notifications_websocket(&url, "fixture-token")
            .await
            .unwrap_err();
        server.join().unwrap();
        assert!(err.to_string().contains("401"), "{err}");
    }
}

fn checked_download_url(value: &str, api_origin: &str) -> Result<url::Url> {
    let origin =
        url::Url::parse(api_origin).map_err(|_| Error::UnsafeWrite {
            message: "invalid API origin".into(),
        })?;
    let url = url::Url::parse(value).map_err(|_| Error::UnsafeWrite {
        message: "invalid attachment URL".into(),
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || !(url.scheme() == "https"
            || (url.scheme() == "http" && url.origin() == origin.origin()))
    {
        return Err(Error::UnsafeWrite {
            message: "unsafe attachment URL".into(),
        });
    }
    Ok(url)
}

#[cfg(test)]
mod native_transport_tests {
    use super::*;
    use std::io::{BufRead as _, Read as _, Write as _};

    #[tokio::test]
    async fn ssh_capability_header_does_not_hide_ssh_ciphers() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut reader =
                std::io::BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut headers = std::collections::HashMap::new();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (key, value) = line.split_once(':').unwrap();
                headers.insert(key.to_lowercase(), value.trim().to_owned());
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            headers
        });
        let client = Client::new("", "", "", None)
            .reqwest_client()
            .await
            .unwrap();
        client
            .get(format!("http://{address}/sync"))
            .send()
            .await
            .unwrap();
        let headers = server.join().unwrap();
        assert_api_identification(&headers);
        let version: Vec<u32> = headers["bitwarden-client-version"]
            .split('.')
            .map(|part| part.parse().unwrap())
            .collect();
        assert!(version.as_slice() >= [2024, 12, 0].as_slice());
        assert!(headers["user-agent"].contains(env!("CARGO_PKG_VERSION")));
    }
    #[test]
    fn explicit_server_type_ignores_inactive_payloads_after_conversion() {
        let value = serde_json::json!({"id":"fixture","name":"encrypted-name","type":2,"reprompt":0,"login":{"username":"encrypted-username"},"secureNote":{"type":0}});
        let cipher: SyncResCipher =
            serde_json::from_value(value.clone()).unwrap();
        assert!(matches!(
            cipher.to_entry(&[]).unwrap().data,
            crate::db::EntryData::SecureNote
        ));
        let mut legacy = value;
        legacy.as_object_mut().unwrap().remove("type");
        let cipher: SyncResCipher = serde_json::from_value(legacy).unwrap();
        assert!(matches!(
            cipher.to_entry(&[]).unwrap().data,
            crate::db::EntryData::Login { .. }
        ));
    }
    #[test]
    fn native_creation_sends_the_correct_cipher_type() {
        for (kind, value) in [
            (2, serde_json::json!("SecureNote")),
            (3, serde_json::json!({"Card":{}})),
            (4, serde_json::json!({"Identity":{}})),
        ] {
            let data: crate::db::EntryData =
                serde_json::from_value(value).unwrap();
            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with("POST /ciphers "));
                let mut length = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line
                        .to_ascii_lowercase()
                        .strip_prefix("content-length:")
                    {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let body: serde_json::Value =
                    serde_json::from_slice(&body).unwrap();
                assert_eq!(body["encryptedFor"], "synthetic-user");
                assert_eq!(body["type"], kind);
                assert_eq!(body["login"], serde_json::Value::Null);
                if kind == 2 {
                    assert_eq!(body["secureNote"]["type"], 0);
                }
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
            });
            Client::new(&format!("http://{address}"), "", "", None)
                .add(
                    "header.eyJzdWIiOiJzeW50aGV0aWMtdXNlciJ9.signature",
                    "encrypted-name",
                    &data,
                    None,
                    None,
                )
                .unwrap();
            server.join().unwrap();
        }
    }

    #[test]
    fn attachment_multipart_is_binary_and_preserves_every_byte() {
        check_attachment_upload_transport(false);
    }

    #[test]
    fn signed_blob_upload_has_no_vault_identification_or_authorization() {
        check_attachment_upload_transport(true);
    }

    fn check_attachment_upload_transport(signed_blob: bool) {
        let encrypted = vec![0xff; 65];
        let expected = encrypted.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for index in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with(if index == 0 {
                    "POST /ciphers/fixture/attachment/v2 "
                } else if signed_blob {
                    "PUT /signed-blob?sig=synthetic "
                } else {
                    "POST /ciphers/fixture/attachment/fixture-attachment "
                }));
                let mut length = 0;
                let mut headers = std::collections::HashMap::new();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        headers.insert(
                            name.to_ascii_lowercase(),
                            value.trim().to_owned(),
                        );
                    }
                    if let Some(value) = line
                        .to_ascii_lowercase()
                        .strip_prefix("content-length:")
                    {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                if index == 0 || !signed_blob {
                    assert_api_identification(&headers);
                    assert_eq!(
                        headers.get("authorization").map(String::as_str),
                        Some("Bearer synthetic-token")
                    );
                } else {
                    for name in [
                        "authorization",
                        "bitwarden-client-name",
                        "bitwarden-client-version",
                        "device-type",
                    ] {
                        assert!(
                            !headers.contains_key(name),
                            "signed blob received {name}"
                        );
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let response = if index == 0 {
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&body)
                            .unwrap()["fileSize"],
                        expected.len()
                    );
                    serde_json::json!({"attachmentId":"fixture-attachment","fileUploadType":if signed_blob {1} else {0},"url":format!("http://{address}/signed-blob?sig=synthetic")}).to_string()
                } else if signed_blob {
                    assert_eq!(body, expected);
                    assert_eq!(
                        headers["content-type"],
                        "application/octet-stream"
                    );
                    assert_eq!(headers["x-ms-blob-type"], "BlockBlob");
                    "{}".to_owned()
                } else {
                    assert!(body
                        .windows(expected.len())
                        .any(|window| window == expected));
                    assert!(String::from_utf8_lossy(&body)
                        .contains("Content-Type: application/octet-stream"));
                    "{}".to_owned()
                };
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response).unwrap();
            }
        });
        let attachment =
            Client::new(&format!("http://{address}"), "", "", None)
                .attachment_upload(
                    "synthetic-token",
                    "fixture",
                    "encrypted-filename",
                    "encrypted-key",
                    &encrypted,
                )
                .unwrap();
        assert_eq!(attachment, "fixture-attachment");
        server.join().unwrap();
    }

    #[test]
    fn rejects_unsafe_signed_urls_without_leaking_them() {
        for url in [
            "http://other.invalid/file",
            "https://user:password@example.invalid/file",
            "file:///tmp/file",
            "not a url",
        ] {
            assert!(checked_download_url(
                url,
                "https://vault.example.invalid/api"
            )
            .is_err());
        }
        assert!(checked_download_url(
            "http://localhost/file",
            "http://localhost/api"
        )
        .is_ok());
        assert!(checked_download_url(
            "https://storage.example.invalid/file?token=synthetic",
            "https://vault.example.invalid/api"
        )
        .is_ok());
    }
}
