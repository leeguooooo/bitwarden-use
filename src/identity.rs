use crate::prelude::*;

use sha1::Digest as _;

pub struct Identity {
    pub email: String,
    pub keys: crate::locked::Keys,
    pub master_password_hash: crate::locked::PasswordHash,
}

impl Identity {
    pub fn new(
        email: &str,
        password: &crate::locked::Password,
        kdf: crate::api::KdfType,
        iterations: u32,
        memory: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self> {
        let email = email.trim().to_lowercase();

        let iterations = std::num::NonZeroU32::new(iterations)
            .ok_or(Error::Pbkdf2ZeroIterations)?;

        let mut keys = crate::locked::Vec::new();
        keys.extend(std::iter::repeat_n(0, 64));

        let enc_key = &mut keys.data_mut()[0..32];

        match kdf {
            crate::api::KdfType::Pbkdf2 => {
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                    password.password(),
                    email.as_bytes(),
                    iterations.get(),
                    enc_key,
                )
                .map_err(|_| Error::Pbkdf2)?;
            }

            crate::api::KdfType::Argon2id => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(email.as_bytes());
                let salt = hasher.finalize();

                let argon2_config = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    argon2::Params::new(
                        memory.unwrap() * 1024,
                        iterations.get(),
                        parallelism.unwrap(),
                        Some(32),
                    )
                    .unwrap(),
                );
                argon2::Argon2::hash_password_into(
                    &argon2_config,
                    password.password(),
                    &salt,
                    enc_key,
                )
                .map_err(|_| Error::Argon2)?;
            }
        }

        let mut hash = crate::locked::Vec::new();
        hash.extend(std::iter::repeat_n(0, 32));
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            enc_key,
            password.password(),
            1,
            hash.data_mut(),
        )
        .map_err(|_| Error::Pbkdf2)?;

        let hkdf = hkdf::Hkdf::<sha2::Sha256>::from_prk(enc_key)
            .map_err(|_| Error::HkdfExpand)?;
        hkdf.expand(b"enc", enc_key)
            .map_err(|_| Error::HkdfExpand)?;
        let mac_key = &mut keys.data_mut()[32..64];
        hkdf.expand(b"mac", mac_key)
            .map_err(|_| Error::HkdfExpand)?;

        let keys = crate::locked::Keys::new(keys);
        let master_password_hash = crate::locked::PasswordHash::new(hash);

        Ok(Self {
            email: email.clone(),
            keys,
            master_password_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2id_identity_matches_reference_vectors() {
        // Generated independently with argon2-cffi 25.1.0 (libargon2 v19),
        // hashlib PBKDF2 and HMAC-SHA256. Memory is 8 MiB, time cost is 2.
        // Pin derived encryption/MAC keys and the login hash across upgrades.
        let vectors = [
            (
                1,
                "43a8bb12cac840a084fda7b7cf3ecc6f7e63ae7c5d2300357da336f57489da0b",
                "9bb2ff277d2aeeb97e7016fcb7e905c87a672966e6e7d9f5814fc394893e4b0f",
                "95189bdee0e8bfa8cb21552e57cae2e1b9389a559363a31ce25f64281cda5fb0",
            ),
            (
                2,
                "e8c938d76e87a7640c0124003cb5978bd3426702c00c9bcab149682e8f8388b5",
                "4fe655b05b93f9b22ca2f645a839ce4dd8ae49c211d2d2979fe588908fa89679",
                "a9512d728128d30711c06b959e35b055cddc55cadaae44810a107ce6068db2a5",
            ),
        ];
        let mut password = crate::locked::Vec::new();
        password.extend(b"compatibility-test-password".iter().copied());
        let password = crate::locked::Password::new(password);
        for (parallelism, enc, mac, hash) in vectors {
            let identity = Identity::new(
                "  Fixture@Example.Invalid  ",
                &password,
                crate::api::KdfType::Argon2id,
                2,
                Some(8),
                Some(parallelism),
            )
            .unwrap();
            assert_eq!(identity.email, "fixture@example.invalid");
            for (actual, expected) in [
                (identity.keys.enc_key(), enc),
                (identity.keys.mac_key(), mac),
                (identity.master_password_hash.hash(), hash),
            ] {
                let expected: Vec<u8> = (0..expected.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&expected[i..i + 2], 16).unwrap()
                    })
                    .collect();
                assert_eq!(actual, expected);
            }
        }
    }
}
