// Copyright (C) 2026 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-only

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("required environment variable {0} is not set")]
    Missing(&'static str),
    #[error("environment variable {key} is invalid: {reason}")]
    Invalid { key: &'static str, reason: String },
}

/// Read a required env var, trimming and rejecting empty values.
pub fn required_var(key: &'static str) -> Result<String, ConfigError> {
    let raw = std::env::var(key).map_err(|_| ConfigError::Missing(key))?;
    let value = raw.trim();
    if value.is_empty() {
        return Err(ConfigError::Invalid {
            key,
            reason: "must not be empty".to_string(),
        });
    }
    Ok(value.to_string())
}

pub fn parse_var<T>(key: &'static str, default: &str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let raw = std::env::var(key).unwrap_or_else(|_| default.to_string());
    raw.parse().map_err(|e: T::Err| ConfigError::Invalid {
        key,
        reason: e.to_string(),
    })
}

/// Reject a numeric value equal to its type's default (i.e. zero).
pub fn positive<T>(key: &'static str, value: T) -> Result<T, ConfigError>
where
    T: Default + PartialEq,
{
    if value == T::default() {
        return Err(ConfigError::Invalid {
            key,
            reason: "must be at least 1".to_string(),
        });
    }
    Ok(value)
}

/// The public half of the published development JWT seed (`[0x01; 32]`).
const DEV_JWT_PUBLIC_KEY: [u8; 32] = [
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];

/// Key material that has been published in this repository's history as a
/// development default. Anyone can read it, so no process may boot on it.
///
/// Compared as DECODED bytes, so every encoding of the same value (hex with or
/// without `0x`, base64) is caught.
const PUBLISHED_DEV_SECRETS: &[&[u8]] = &[
    // JWT_ED25519_SECRET dev seed, `0x0101…01`.
    &[0x01; 32],
    // Its public key, the JWT_ED25519_PUBLIC_KEY dev default.
    &DEV_JWT_PUBLIC_KEY,
    // TURN_SECRET dev default (base64 `ZGV2LW9ubHktdHVybi1zZWNyZXQtY2hhbmdlLW1l`).
    b"dev-only-turn-secret-change-me",
    // Earlier TURN_SECRET dev default: 32 `B` characters (base64 `QkJC…QkI=`).
    &[b'B'; 32],
];

/// Refuse key material that has been published as a development default.
///
/// `bytes` is the decoded value of `key`. Returns [`ConfigError::Invalid`]
/// naming the variable when it matches a published value.
pub fn reject_dev_secret(key: &'static str, bytes: &[u8]) -> Result<(), ConfigError> {
    if PUBLISHED_DEV_SECRETS.contains(&bytes) {
        return Err(ConfigError::Invalid {
            key,
            reason: "is a published development value; generate a fresh one \
                     (see .env.example)"
                .to_string(),
        });
    }
    Ok(())
}

/// Load verify-only key material: `JWT_JWKS_JSON` (an inline JWKS document, as
/// served by device-attestation at `/.well-known/jwks.json`) wins; otherwise
/// `JWT_ED25519_PUBLIC_KEY` (32-byte hex, optional `0x`) pins a single key.
///
/// The published development public key is refused on either path.
pub fn jwt_verifier_from_env() -> Result<jwt_verify::Verifier, ConfigError> {
    let jwks = std::env::var("JWT_JWKS_JSON").ok();
    let public_key = std::env::var("JWT_ED25519_PUBLIC_KEY").ok();
    jwt_verifier_from_values(jwks.as_deref(), public_key.as_deref())
}

/// Refuse a JWKS document that carries the published development key.
///
/// Only the `x` member matters: it is the Ed25519 public key, base64url
/// without padding (RFC 8037). Structural problems are left to
/// [`jwt_verify::Verifier::from_jwks`], which reports them.
fn reject_dev_jwks(jwks: &str) -> Result<(), ConfigError> {
    use base64::Engine as _;

    let Ok(doc) = serde_json::from_str::<serde_json::Value>(jwks) else {
        return Ok(());
    };
    let xs = doc
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|key| key.get("x").and_then(serde_json::Value::as_str));
    for x in xs {
        if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x) {
            reject_dev_secret("JWT_JWKS_JSON", &bytes)?;
        }
    }
    Ok(())
}

fn jwt_verifier_from_values(
    jwks: Option<&str>,
    public_key: Option<&str>,
) -> Result<jwt_verify::Verifier, ConfigError> {
    if let Some(jwks) = jwks.filter(|value| !value.trim().is_empty()) {
        reject_dev_jwks(jwks)?;
        return jwt_verify::Verifier::from_jwks(jwks).map_err(|e| ConfigError::Invalid {
            key: "JWT_JWKS_JSON",
            reason: e.to_string(),
        });
    }

    let raw = public_key
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConfigError::Missing(
            "JWT_JWKS_JSON or JWT_ED25519_PUBLIC_KEY",
        ))?;
    let trimmed = raw.trim();
    let bytes: [u8; 32] = hex::decode(trimmed.strip_prefix("0x").unwrap_or(trimmed))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ConfigError::Invalid {
            key: "JWT_ED25519_PUBLIC_KEY",
            reason: "expected 32 bytes of hex".to_string(),
        })?;
    reject_dev_secret("JWT_ED25519_PUBLIC_KEY", &bytes)?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|e| ConfigError::Invalid {
            key: "JWT_ED25519_PUBLIC_KEY",
            reason: format!("not a valid Ed25519 public key: {e}"),
        })?;
    Ok(jwt_verify::Verifier::from_public_key(None, key.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_operational_values() {
        assert!(matches!(
            positive("RATE_LIMIT", 0_u64),
            Err(ConfigError::Invalid { key: "RATE_LIMIT", reason })
                if reason == "must be at least 1"
        ));
        assert!(positive("RATE_LIMIT", 30_u64).is_ok());
    }

    /// Public key of the seed `[0x07; 32]`: a test-only value, never published
    /// as a default.
    fn test_public_key() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[0x07; 32])
            .verifying_key()
            .to_bytes()
    }

    fn jwks_with(x: &[u8]) -> String {
        use base64::Engine as _;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
        format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"k1","x":"{x}"}}]}}"#
        )
    }

    #[test]
    fn empty_jwks_falls_back_to_pinned_public_key() {
        let public_key = format!("0x{}", hex::encode(test_public_key()));
        assert!(jwt_verifier_from_values(Some("  "), Some(&public_key)).is_ok());
    }

    #[test]
    fn missing_key_material_is_a_hard_error() {
        assert!(matches!(
            jwt_verifier_from_values(None, None),
            Err(ConfigError::Missing(_))
        ));
        // Compose passes an unset key through as an empty string.
        assert!(matches!(
            jwt_verifier_from_values(Some(""), Some("  ")),
            Err(ConfigError::Missing(_))
        ));
    }

    #[test]
    fn published_dev_values_are_refused_in_every_encoding() {
        use base64::Engine as _;

        let seed = [0x01_u8; 32];
        assert!(reject_dev_secret("K", &seed).is_err());
        assert!(reject_dev_secret("K", &hex::decode("01".repeat(32)).unwrap()).is_err());
        let b64 = base64::engine::general_purpose::STANDARD.encode(seed);
        assert!(reject_dev_secret(
            "K",
            &base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap()
        )
        .is_err());
        assert!(reject_dev_secret("K", b"dev-only-turn-secret-change-me").is_err());
        assert!(reject_dev_secret("K", &[b'B'; 32]).is_err());
        assert!(reject_dev_secret("K", &DEV_JWT_PUBLIC_KEY).is_err());

        assert!(reject_dev_secret("K", &[0x07; 32]).is_ok());
        assert!(reject_dev_secret("K", &test_public_key()).is_ok());
    }

    #[test]
    fn dev_public_key_is_refused_as_a_pinned_key() {
        for public_key in [
            "0x8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        ] {
            assert!(matches!(
                jwt_verifier_from_values(None, Some(public_key)),
                Err(ConfigError::Invalid {
                    key: "JWT_ED25519_PUBLIC_KEY",
                    ..
                })
            ));
        }
    }

    #[test]
    fn dev_public_key_is_refused_inside_a_jwks_document() {
        assert!(matches!(
            jwt_verifier_from_values(Some(&jwks_with(&DEV_JWT_PUBLIC_KEY)), None),
            Err(ConfigError::Invalid {
                key: "JWT_JWKS_JSON",
                ..
            })
        ));
        assert!(jwt_verifier_from_values(Some(&jwks_with(&test_public_key())), None).is_ok());
    }

    #[test]
    fn dev_public_key_constant_matches_the_dev_seed() {
        let derived = ed25519_dalek::SigningKey::from_bytes(&[0x01; 32])
            .verifying_key()
            .to_bytes();
        assert_eq!(derived, DEV_JWT_PUBLIC_KEY);
    }
}
