//! Watchdog and updater. Sync std only: no async runtime and no network code.
//!
//! The watchdog supervises the agent binary of the active A/B slot, verifies
//! releases the agent staged in `pending/` against the compiled-in root keys
//! (independently of the agent), installs them into the inactive slot as a
//! trial and rolls back trials that do not become healthy.
//!
//! Root layout: `slots/a/`, `slots/b/`, `bootstrap/` (installer-owned, never
//! written here), `pending/` and `state.json`.

pub mod apply;
pub mod state;
pub mod supervisor;

use std::time::{SystemTime, UNIX_EPOCH};

use rmm_trust::keys::PublicKey;

/// File name of the agent binary inside a slot.
pub const AGENT_FILE: &str = if cfg!(windows) {
    "rmm-agent.exe"
} else {
    "rmm-agent"
};

/// Release platform string of this build, e.g. `linux-x86_64`.
pub fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Current Unix time in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write one transition as a JSON line on stderr.
pub fn log(event: &str, fields: serde_json::Value) {
    let mut line = serde_json::Map::new();
    line.insert("ts".into(), now_secs().into());
    line.insert("component".into(), "rmm-watchdog".into());
    line.insert("event".into(), event.into());
    if let serde_json::Value::Object(extra) = fields {
        line.extend(extra);
    }
    eprintln!("{}", serde_json::Value::Object(line));
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out[i] = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

/// Parse compiled-in root keys (comma-separated 64-char hex) and the optional
/// threshold, which defaults to the number of keys (same rules as the agent).
pub fn parse_roots(keys: &str, threshold: Option<&str>) -> Result<(Vec<PublicKey>, u8), String> {
    let mut out = Vec::new();
    for part in keys.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let raw = parse_hex32(part).ok_or("compiled root key is not 32 hex bytes")?;
        out.push(PublicKey::from_bytes(&raw).map_err(|e| format!("compiled root key: {e}"))?);
    }
    let threshold = match threshold {
        Some(t) => t
            .trim()
            .parse::<u8>()
            .map_err(|_| "RMM_ROOT_THRESHOLD is not a number".to_owned())?,
        None => u8::try_from(out.len()).unwrap_or(u8::MAX),
    };
    Ok((out, threshold))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roots_parse_like_the_agent() {
        let k = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
        let (keys, t) = parse_roots(&format!(" {k} ,"), None).expect("parse");
        assert_eq!((keys.len(), t), (1, 1));
        assert_eq!(parse_roots(k, Some("2")).expect("parse").1, 2);
        assert!(parse_roots("abcd", None).is_err());
        assert!(parse_roots(k, Some("x")).is_err());
        assert_eq!(parse_roots("", None).expect("empty").1, 0);
    }

    #[test]
    fn hex_is_lower_case() {
        assert_eq!(hex(&[0x00, 0xAB, 0x7f]), "00ab7f");
    }
}
