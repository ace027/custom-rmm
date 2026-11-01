//! `dev-token`: mint an RS256 JWT for local development against an API that
//! runs with `RMM_AUTH_ALLOW_DEV=1`.

use anyhow::{Context, Result, anyhow};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rmm_api::auth::{DEV_ISSUER, rsa_private_der_from_pem};

/// Sign a development token for `sub` holding `role`, valid for `ttl_secs`.
pub fn mint(
    key_pem: &[u8],
    audience: &str,
    role: &str,
    sub: &str,
    ttl_secs: u64,
    now: u64,
) -> Result<String> {
    let der = rsa_private_der_from_pem(key_pem).map_err(|e| anyhow!("dev key: {e}"))?;
    let claims = serde_json::json!({
        "iss": DEV_ISSUER,
        "aud": audience,
        "sub": sub,
        "oid": sub,
        "name": sub,
        "roles": [role],
        "iat": now,
        "nbf": now,
        "exp": now.saturating_add(ttl_secs),
    });
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_der(&der),
    )
    .context("sign token")
}

/// Mint using `RMM_AUTH_DEV_KEY_FILE` and `RMM_ENTRA_AUDIENCE`.
pub fn run(role: &str, sub: &str, ttl_secs: u64) -> Result<String> {
    let path =
        std::env::var("RMM_AUTH_DEV_KEY_FILE").context("RMM_AUTH_DEV_KEY_FILE is not set")?;
    let audience = std::env::var("RMM_ENTRA_AUDIENCE").context("RMM_ENTRA_AUDIENCE is not set")?;
    let pem = std::fs::read(&path).with_context(|| format!("read {path}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock")?
        .as_secs();
    mint(&pem, &audience, role, sub, ttl_secs, now)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use rmm_api::auth::{AuthConfig, Authenticator};

    const KEY_A_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAnwjZGao2uARmrdBW/iGXPrOmw0RZoMXO2hiNqo3Moq61Byvo
OuFnBCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXNC80T/sH28J4XX2+IRFpF8ohQyBN8
N6zfoU+iUzRi+r0S63Gh81s2ySEJ2foLkLpPeHEgIQoMbDWH88oPIl76kZfW4rl4
KWCd4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMmbwAqtn4x3KrazWuBMAM5PUyVpG8A
Se29uGszpsaifMVqICFmc+hjYZ8fQiwCxD1kVXKoEi3x+tP+S06CBQ7ab5OmWJi0
HT0spk0KPoelLvsK0KwCiPHPxS7J/uqU2aJaXwIDAQABAoIBABe5qTGz+//N4EeT
6jZ1amvXP0yoOLrMZ8SPnyrPhrTKXYVZXobSM50h+Y5ALZQz1WuedMr3xB/Fm+Pv
H3IrzVAyYwZBh4Zz/0aki+6ujPrWrT578a8YojAdgjjpes6vQFBRnniAphaxUBft
vqXztYFhVwq2xg2qmsKa5VEaXEU15nqi0EtYe5+VzZbOMI2NRJ2j5lW12S3yUo58
FbsTYbcoP5gXX1UKyq5qxRe8L8tt/OMyLyfujrOzN7UTVor1pNXDprhxPeOziZjP
kyXCYVb67rz+2KZMrYdD5a19j2MoxTzh+9y8X22kYUeOnhvCvjczEfs9jnulO0p/
kF6YCPECgYEA04Y1RV+RZxXDRJV+J6Yb/XpEMULmA9uM86XdsblRj29bk0AAgTNt
3oF7NdweSfJPpfY9RqaSQIFcRLURvb+zkycEfj5ippAeoLjNhMNY+gL4kSIhmQFU
nguv8ugeCP5OowdE0CfFSlXEa5mnKKMDh75WhY3Dw4RNUMhrThCSzscCgYEAwHlC
N39LvthIJr2fy44n5cPQ1TBLMAgdFrtwOF2yPQr0kFT5+VY0sUY3/6Scpz6v8oDk
6yYZ4cEngmd7CX4yfxbYWEzGUxbaFnj/6sM91Kv3Yw5hTCQC+xNOGO9ZKgeqcGH5
kAv69NOCtEYKoArOOHml66BOwkCgWxUQatYkX6kCgYEA0pQdnH7T5mhICZM6EIbR
/rsmAFS1YMnFvRo3ZqMzizQ1Wpaw6e8lRgppeuk0TjGpEXPe9OMHXqhqDwykKN8c
Czcgxf2dgGyh0Sepkq5Xei5S/0mXYRduAhlohM6IeDOUXcDyxLeTNbnE3coOG+qN
rSnUQQktBwxDXFTqXsEpJikCgYBFuuiJcJ3Be1vQZTyCI3NC44lB4ygqM5ZOSQPj
99X+FXz62T5i3Z9jZhwdisaSNLzLr3S/2GLiDfdBYDoL+2NR9bXVb6MeMRY7tASL
ScaZyN9sTKZlTlqiGaFemUAFYReXdXdTf3OgxQwCQanRx3hkr3W0ArTl3UH7HYuA
GSq+WQKBgDkV2DcRKvDK1RIlEPYSyXnP3V0xQ5j3s/xZbfqzqMq2SYYbPA3r23Ty
kj4UNoQqBmzJ5CVUWUx6MLTqX3IFCJErSXbfjiD6CSWl6rObT4VUOoeg9Qho2MBJ
SWf9oefLMwUqfemP0ZQM+bJ2VQMG5rll3zGtfkOS6T0JN70mQNIs
-----END RSA PRIVATE KEY-----
";
    const KEY_A_PUB_SPKI: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnwjZGao2uARmrdBW/iGX
PrOmw0RZoMXO2hiNqo3Moq61ByvoOuFnBCcIM5NHrOB9qxvKuhPS2MuzsCpm1PXN
C80T/sH28J4XX2+IRFpF8ohQyBN8N6zfoU+iUzRi+r0S63Gh81s2ySEJ2foLkLpP
eHEgIQoMbDWH88oPIl76kZfW4rl4KWCd4U3g6ATgDpT1GPeD6btEfAqetPPY8ZMm
bwAqtn4x3KrazWuBMAM5PUyVpG8ASe29uGszpsaifMVqICFmc+hjYZ8fQiwCxD1k
VXKoEi3x+tP+S06CBQ7ab5OmWJi0HT0spk0KPoelLvsK0KwCiPHPxS7J/uqU2aJa
XwIDAQAB
-----END PUBLIC KEY-----
";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn auth(allow_dev: bool) -> Authenticator {
        Authenticator::from_config(AuthConfig {
            tenant_id: None,
            audience: "api://rmm".into(),
            allow_dev,
            dev_pubkey_pem: Some(KEY_A_PUB_SPKI.as_bytes().to_vec()),
        })
        .unwrap()
    }

    #[tokio::test]
    async fn minted_token_is_accepted_only_with_allow_dev() {
        let t = mint(
            KEY_A_PEM.as_bytes(),
            "api://rmm",
            "RMM.Admin",
            "dev-admin",
            3600,
            now(),
        )
        .unwrap();
        let c = auth(true).verify(&t).await.unwrap();
        assert_eq!(c.sub, "dev-admin");
        assert_eq!(c.roles, vec!["RMM.Admin".to_string()]);
        assert!(auth(false).verify(&t).await.is_err());
    }

    #[tokio::test]
    async fn wrong_audience_and_expired_tokens_fail() {
        let t = mint(
            KEY_A_PEM.as_bytes(),
            "api://other",
            "RMM.Admin",
            "x",
            3600,
            now(),
        )
        .unwrap();
        assert!(auth(true).verify(&t).await.is_err());
        let t = mint(
            KEY_A_PEM.as_bytes(),
            "api://rmm",
            "RMM.Admin",
            "x",
            10,
            now() - 7200,
        )
        .unwrap();
        assert!(auth(true).verify(&t).await.is_err());
    }
}
