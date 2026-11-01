//! NATS JWT encoding, agent user claims and nonce signature checks.
#![allow(clippy::unwrap_used, clippy::expect_used)]

// The package has no library target, so the module is compiled in directly.
#[allow(dead_code)]
#[path = "../src/natsjwt.rs"]
mod natsjwt;

use data_encoding::BASE64URL_NOPAD;
use nkeys::KeyPair;
use rmm_db::repo::AgentAuthRow;
use serde_json::{Value, json};
use uuid::Uuid;

use natsjwt::*;

fn agent(client: u128, agent: u128) -> AgentAuthRow {
    AgentAuthRow {
        agent_id: Uuid::from_u128(agent),
        client_id: Uuid::from_u128(client),
        device_id: Uuid::from_u128(agent + 1000),
        status: "active".into(),
        client_status: "active".into(),
        nkey: KeyPair::new_user().public_key(),
    }
}

fn parts(jwt: &str) -> (Value, Value, Vec<u8>) {
    let p: Vec<&str> = jwt.split('.').collect();
    assert_eq!(p.len(), 3);
    assert!(!jwt.contains('='), "no padding");
    let h = serde_json::from_slice(&BASE64URL_NOPAD.decode(p[0].as_bytes()).unwrap()).unwrap();
    let c = serde_json::from_slice(&BASE64URL_NOPAD.decode(p[1].as_bytes()).unwrap()).unwrap();
    (h, c, BASE64URL_NOPAD.decode(p[2].as_bytes()).unwrap())
}

#[test]
fn encode_then_verify_with_account_key() {
    let issuer = KeyPair::new_account();
    let jwt = encode_jwt(&json!({"sub": "x", "jti": "ignored"}), &issuer);
    let (h, c, sig) = parts(&jwt);
    assert_eq!(h, json!({"typ": "JWT", "alg": "ed25519-nkey"}));
    assert_eq!(c["iss"], issuer.public_key());
    assert!(c["iat"].as_u64().unwrap() > 1_700_000_000);

    let signing_input = jwt.rsplit_once('.').unwrap().0;
    let verifier = KeyPair::from_public_key(&issuer.public_key()).unwrap();
    verifier.verify(signing_input.as_bytes(), &sig).unwrap();

    // jti is base32(SHA-256(claims without jti)).
    let mut unsigned = c.clone();
    let jti = unsigned.as_object_mut().unwrap().remove("jti").unwrap();
    use sha2::Digest;
    let h: [u8; 32] = sha2::Sha256::digest(unsigned.to_string().as_bytes()).into();
    assert_eq!(jti, data_encoding::BASE32_NOPAD.encode(&h));

    assert_eq!(decode_verified(&jwt, PREFIX_ACCOUNT).unwrap(), c);
    assert!(
        decode_verified(&jwt, PREFIX_SERVER).is_err(),
        "issuer type is enforced"
    );

    // Tampering with the claims breaks the signature.
    let p: Vec<&str> = jwt.split('.').collect();
    let forged = BASE64URL_NOPAD.encode(
        json!({"sub": "y", "iss": issuer.public_key()})
            .to_string()
            .as_bytes(),
    );
    let tampered = format!("{}.{}.{}", p[0], forged, p[2]);
    assert!(decode_verified(&tampered, PREFIX_ACCOUNT).is_err());
}

#[test]
fn user_claims_contain_exactly_the_agent_subjects() {
    let a = agent(0xA, 0x1);
    let (c, id) = (a.client_id, a.agent_id);
    let user = KeyPair::new_user().public_key();
    let now = 1_800_000_000;
    let claims = user_claims(&user, &a, now);

    assert_eq!(claims["sub"], user);
    assert_eq!(claims["aud"], "RMM");
    let exp = claims["exp"].as_u64().unwrap();
    assert!(exp > now && exp - now <= 3600, "expiry <= 1 h");
    let n = &claims["nats"];
    assert_eq!(n["type"], "user");
    assert_eq!(n["version"], 2);
    assert_eq!(n["allowed_connection_types"], json!(["WEBSOCKET"]));
    assert_eq!(n["subs"], -1);

    let pubs: Vec<String> = serde_json::from_value(n["pub"]["allow"].clone()).unwrap();
    assert_eq!(
        pubs,
        vec![
            format!("telemetry.{c}.{id}.>"),
            format!("result.{c}.{id}"),
            format!("shell.{id}.*.out"),
            "svc.trust.latest".to_owned(),
            format!("$JS.API.CONSUMER.INFO.CMD.agent_{id}"),
            format!("$JS.API.CONSUMER.MSG.NEXT.CMD.agent_{id}"),
            format!("$JS.ACK.CMD.agent_{id}.>"),
        ]
    );
    let subs: Vec<String> = serde_json::from_value(n["sub"]["allow"].clone()).unwrap();
    assert_eq!(
        subs,
        vec![
            format!("_INBOX_{id}.>"),
            format!("shell.{id}.*.in"),
            format!("shell.{id}.*.ctl"),
        ]
    );
    assert!(n["pub"].get("deny").is_none() && n["sub"].get("deny").is_none());

    // Nothing of another client or agent leaks in.
    let other = agent(0xB, 0x2);
    let text = claims.to_string();
    assert!(!text.contains(&other.client_id.to_string()));
    assert!(!text.contains(&other.agent_id.to_string()));
}

#[test]
fn responses() {
    let server = KeyPair::new_server().public_key();
    let user = KeyPair::new_user().public_key();
    let ok = authorization_response(&user, &server, Some("jwt".into()), None);
    assert_eq!(ok["sub"], user);
    assert_eq!(ok["aud"], server);
    assert_eq!(ok["nats"]["type"], "authorization_response");
    assert_eq!(ok["nats"]["jwt"], "jwt");
    assert!(ok["nats"].get("error").is_none());

    let deny = authorization_response(&user, &server, None, Some("not authorized".into()));
    assert_eq!(deny["nats"]["error"], "not authorized");
    assert!(deny["nats"].get("jwt").is_none(), "a deny carries no jwt");
    let both = authorization_response(&user, &server, Some("jwt".into()), Some("no".into()));
    assert!(
        both["nats"].get("jwt").is_none(),
        "an error wins over a jwt"
    );
    let neither = authorization_response(&user, &server, None, None);
    assert!(neither["nats"].get("error").is_some());
}

/// A request as the server would send it, signed by its server key.
fn request(server: &KeyPair, nonce: &str, client: &KeyPair, sig: &[u8]) -> String {
    let user_nkey = KeyPair::new_user().public_key();
    let claims = json!({
        "sub": user_nkey,
        "aud": "nats-authorization-request",
        "nats": {
            "type": "authorization_request",
            "version": 2,
            "user_nkey": user_nkey,
            "server_id": {"id": server.public_key(), "name": "rmm-dev"},
            "client_info": {"host": "10.0.0.5", "id": 42, "nonce": nonce, "kind": "Client", "type": "websocket"},
            "connect_opts": {"nkey": client.public_key(), "sig": BASE64URL_NOPAD.encode(sig), "name": "rmm-agent/0.1"}
        }
    });
    encode_jwt(&claims, server)
}

#[test]
fn decode_request_and_check_nonce_signature() {
    let server = KeyPair::new_server();
    let client = KeyPair::new_user();
    let nonce = "pmOn8MAV1WwVKOI";
    let jwt = request(
        &server,
        nonce,
        &client,
        &client.sign(nonce.as_bytes()).unwrap(),
    );
    let req = decode_authorization_request(&jwt).unwrap();
    assert_eq!(req.server_id, server.public_key());
    assert_eq!(req.client_info.nonce, nonce);
    assert_eq!(req.client_info.cid, 42);
    assert_eq!(req.client_info.conn_type, "websocket");
    assert_eq!(req.connect_opts.nkey, client.public_key());
    let key = verify_nonce_signature(&req).unwrap();
    assert_eq!(
        public_key_bytes(&client.public_key(), PREFIX_USER).unwrap(),
        key
    );

    // Signature over a different nonce.
    let bad = request(&server, nonce, &client, &client.sign(b"other").unwrap());
    let req = decode_authorization_request(&bad).unwrap();
    assert!(verify_nonce_signature(&req).is_err());

    // Signed by a different key than the claimed nkey.
    let thief = KeyPair::new_user();
    let stolen = request(
        &server,
        nonce,
        &client,
        &thief.sign(nonce.as_bytes()).unwrap(),
    );
    let req = decode_authorization_request(&stolen).unwrap();
    assert!(verify_nonce_signature(&req).is_err());

    // No nonce means no proof.
    let empty = request(&server, "", &client, &client.sign(b"").unwrap());
    let req = decode_authorization_request(&empty).unwrap();
    assert!(verify_nonce_signature(&req).is_err());
}

#[test]
fn request_must_come_from_a_server_key() {
    let client = KeyPair::new_user();
    let nonce = "n";
    let sig = client.sign(nonce.as_bytes()).unwrap();
    // Signed by an account key instead of a server key.
    let acct = KeyPair::new_account();
    assert!(decode_authorization_request(&request(&acct, nonce, &client, &sig)).is_err());
    // Wrong claim type.
    let server = KeyPair::new_server();
    let other = encode_jwt(&json!({"nats": {"type": "user"}}), &server);
    assert!(decode_authorization_request(&other).is_err());
    assert!(decode_authorization_request("a.b").is_err());
}
