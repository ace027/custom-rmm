//! Pure SMBIOS parser for the raw table returned by
//! `GetSystemFirmwareTable('RSMB')`. Compiled on every platform so it can be
//! unit-tested anywhere; every read is bounds-checked and a damaged buffer
//! yields whatever was parsed before the damage instead of panicking.

use rmm_proto::enroll::HwFacts;

/// Size of the `RawSMBIOSData` header: calling method, major, minor, DMI
/// revision (one byte each) and a `u32` table length.
const RAW_HEADER: usize = 8;
/// Size of a structure header: type, length, handle.
const STRUCT_HEADER: usize = 4;

const TYPE_SYSTEM: u8 = 1;
const TYPE_BASEBOARD: u8 = 2;
const TYPE_END: u8 = 127;

/// The string set following a structure's formatted area.
struct Strings<'a>(&'a [u8]);

impl Strings<'_> {
    /// String number `n` (1-based; 0 means "none"), trimmed, `None` if empty.
    fn get(&self, n: u8) -> Option<String> {
        if n == 0 {
            return None;
        }
        let raw = self.0.split(|b| *b == 0).nth(usize::from(n) - 1)?;
        let s = String::from_utf8_lossy(raw).trim().to_owned();
        (!s.is_empty()).then_some(s)
    }
}

/// Format a 16-byte SMBIOS UUID. From SMBIOS 2.6 the first three fields are
/// little endian and are byte-swapped; before that the bytes print as stored.
/// All-zero and all-0xFF values mean "not present".
fn format_uuid(b: &[u8], little_endian_fields: bool) -> Option<String> {
    let b: &[u8; 16] = b.try_into().ok()?;
    if b.iter().all(|x| *x == 0) || b.iter().all(|x| *x == 0xff) {
        return None;
    }
    let mut o = *b;
    if little_endian_fields {
        o[0..4].reverse();
        o[4..6].reverse();
        o[6..8].reverse();
    }
    let h = |s: &[u8]| s.iter().map(|x| format!("{x:02x}")).collect::<String>();
    Some(format!(
        "{}-{}-{}-{}-{}",
        h(&o[0..4]),
        h(&o[4..6]),
        h(&o[6..8]),
        h(&o[8..10]),
        h(&o[10..16])
    ))
}

/// Parse a raw SMBIOS buffer (`RawSMBIOSData` header followed by the
/// structure table) into hardware facts. Missing or damaged data leaves the
/// corresponding fields `None`.
pub fn parse_rsmb(raw: &[u8]) -> HwFacts {
    let mut facts = HwFacts::default();
    let (Some(&major), Some(&minor)) = (raw.get(1), raw.get(2)) else {
        return facts;
    };
    let declared = raw
        .get(4..8)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(0, u32::from_le_bytes);
    let Some(rest) = raw.get(RAW_HEADER..) else {
        return facts;
    };
    // Trust the declared length only as an upper bound.
    let table = rest.get(..declared as usize).unwrap_or(rest);
    let le_uuid = (major, minor) >= (2, 6);

    let mut pos = 0usize;
    let (mut seen_system, mut seen_board) = (false, false);
    while let Some(head) = table.get(pos..pos + STRUCT_HEADER) {
        let (ty, flen) = (head[0], usize::from(head[1]));
        if ty == TYPE_END || flen < STRUCT_HEADER {
            break;
        }
        let Some(formatted) = table.get(pos..pos + flen) else {
            break;
        };
        let str_start = pos + flen;
        // The string set ends at a double NUL (a lone NUL pair when empty).
        let after = &table[str_start..];
        let (strings, next) = match after.windows(2).position(|w| w == [0, 0]) {
            Some(i) => (&after[..i], str_start + i + 2),
            None => (after, table.len()),
        };
        let strings = Strings(strings);
        let at = |i: usize| formatted.get(i).copied().unwrap_or(0);

        match ty {
            TYPE_SYSTEM if !seen_system => {
                seen_system = true;
                facts.manufacturer = strings.get(at(4));
                facts.model = strings.get(at(5));
                facts.system_serial = strings.get(at(7));
                facts.smbios_uuid = formatted.get(8..24).and_then(|u| format_uuid(u, le_uuid));
            }
            TYPE_BASEBOARD if !seen_board => {
                seen_board = true;
                facts.board_serial = strings.get(at(7));
            }
            _ => {}
        }
        if next >= table.len() {
            break;
        }
        pos = next;
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_proto::enroll::{FpStrength, fingerprint};

    /// Build a structure: header, formatted body (padded to `flen`), strings.
    fn structure(ty: u8, flen: usize, body: &[(usize, u8)], strings: &[&str]) -> Vec<u8> {
        let mut f = vec![0u8; flen];
        f[0] = ty;
        f[1] = flen as u8;
        for &(i, v) in body {
            f[i] = v;
        }
        let mut out = f;
        if strings.is_empty() {
            out.extend_from_slice(&[0, 0]);
        } else {
            for s in strings {
                out.extend_from_slice(s.as_bytes());
                out.push(0);
            }
            out.push(0);
        }
        out
    }

    fn raw(major: u8, minor: u8, table: &[u8]) -> Vec<u8> {
        let mut r = vec![0, major, minor, 0];
        r.extend_from_slice(&(table.len() as u32).to_le_bytes());
        r.extend_from_slice(table);
        r
    }

    fn with_uuid(mut s: Vec<u8>, uuid: [u8; 16]) -> Vec<u8> {
        s[8..24].copy_from_slice(&uuid);
        s
    }

    #[test]
    fn smbios_3x_with_junk_serials() {
        let uuid = [
            0x44, 0x45, 0x4c, 0x4c, 0x42, 0x00, 0x10, 0x35, 0x80, 0x51, 0xb7, 0xc0, 0x4f, 0x4c,
            0x4c, 0x32,
        ];
        let mut t = structure(0, 0x18, &[], &["BIOS vendor"]); // type 0 is skipped
        t.extend(with_uuid(
            structure(
                TYPE_SYSTEM,
                0x1b,
                &[(4, 1), (5, 2), (7, 3)],
                &["Dell Inc.", "OptiPlex 7090", "To be filled by O.E.M."],
            ),
            uuid,
        ));
        t.extend(structure(
            TYPE_BASEBOARD,
            0x0f,
            &[(4, 1), (7, 2)],
            &["Dell Inc.", "Default string"],
        ));
        t.extend(structure(TYPE_END, 4, &[], &[]));
        let f = parse_rsmb(&raw(3, 4, &t));
        assert_eq!(f.manufacturer.as_deref(), Some("Dell Inc."));
        assert_eq!(f.model.as_deref(), Some("OptiPlex 7090"));
        assert_eq!(f.system_serial.as_deref(), Some("To be filled by O.E.M."));
        assert_eq!(f.board_serial.as_deref(), Some("Default string"));
        // Fields 1-3 are byte-swapped for SMBIOS >= 2.6.
        assert_eq!(
            f.smbios_uuid.as_deref(),
            Some("4c4c4544-0042-3510-8051-b7c04f4c4c32")
        );
        // Junk serials make the fingerprint weak.
        assert_eq!(fingerprint(&f).1, FpStrength::Weak);
    }

    #[test]
    fn smbios_24_prints_uuid_as_stored() {
        let uuid = [
            0x4c, 0x4c, 0x45, 0x44, 0x00, 0x42, 0x35, 0x10, 0x80, 0x51, 0xb7, 0xc0, 0x4f, 0x4c,
            0x4c, 0x32,
        ];
        let mut t = with_uuid(
            structure(
                TYPE_SYSTEM,
                0x19,
                &[(4, 1), (5, 2), (7, 3)],
                &["ACME", "Box", "SN123"],
            ),
            uuid,
        );
        t.extend(structure(TYPE_BASEBOARD, 0x0f, &[(7, 1)], &["BRD9"]));
        let f = parse_rsmb(&raw(2, 4, &t));
        assert_eq!(
            f.smbios_uuid.as_deref(),
            Some("4c4c4544-0042-3510-8051-b7c04f4c4c32")
        );
        assert_eq!(f.system_serial.as_deref(), Some("SN123"));
        assert_eq!(f.board_serial.as_deref(), Some("BRD9"));
        assert_eq!(fingerprint(&f).1, FpStrength::Strong);
    }

    #[test]
    fn all_zero_and_all_ff_uuid_are_absent() {
        for fill in [0x00, 0xff] {
            let t = with_uuid(structure(TYPE_SYSTEM, 0x19, &[], &[]), [fill; 16]);
            assert_eq!(parse_rsmb(&raw(3, 0, &t)).smbios_uuid, None);
        }
    }

    #[test]
    fn truncated_buffers_never_panic() {
        let mut t = with_uuid(
            structure(TYPE_SYSTEM, 0x1b, &[(4, 1), (7, 2)], &["Maker", "SER"]),
            [1; 16],
        );
        t.extend(structure(TYPE_BASEBOARD, 0x0f, &[(7, 1)], &["BRD"]));
        let full = raw(3, 3, &t);
        for n in 0..full.len() {
            let _ = parse_rsmb(&full[..n]);
        }
        // Cut inside the string set: partial result, manufacturer survives.
        let cut = &full[..RAW_HEADER + 0x1b + 3];
        let f = parse_rsmb(cut);
        assert_eq!(f.manufacturer.as_deref(), Some("Mak"));
        // Cut inside the formatted area: nothing usable.
        assert_eq!(parse_rsmb(&full[..RAW_HEADER + 10]), HwFacts::default());
        assert_eq!(parse_rsmb(&[]), HwFacts::default());
    }

    #[test]
    fn hostile_lengths_are_survivable() {
        // Declared length far beyond the buffer, zero-length structure.
        let mut r = vec![0, 3, 0, 0, 0xff, 0xff, 0xff, 0xff];
        r.extend_from_slice(&[TYPE_SYSTEM, 0, 0, 0, 0, 0]);
        assert_eq!(parse_rsmb(&r), HwFacts::default());
        // String index pointing past the string set.
        let t = structure(TYPE_SYSTEM, 0x19, &[(4, 9), (7, 200)], &["x"]);
        let f = parse_rsmb(&raw(3, 0, &t));
        assert_eq!(f.manufacturer, None);
        assert_eq!(f.system_serial, None);
    }
}
