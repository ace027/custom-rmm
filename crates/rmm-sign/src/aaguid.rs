//! Compiled allowlist of hardware authenticator AAGUIDs a technician list may
//! contain.
//!
//! `YUBIKEY_5_AAGUIDS` lists every FIDO-certified Yubico YubiKey 5 series
//! authenticator model (YubiKey 5 / 5 Nano / 5C / 5C Nano / 5 NFC / 5C NFC /
//! 5Ci, firmware 5.1 through 5.8, including the FIPS, CCN, Enhanced PIN and
//! Enterprise/Consumer profile variants). Preview and release-candidate
//! models that are not FIDO certified are excluded.
//!
//! Source: the AAGUIDs and descriptions of Yubico's metadata statements in the
//! FIDO Alliance Metadata Service (MDS3, <https://mds3.fidoalliance.org/>,
//! BLOB no. 294), retrieved 2026-11-01; see also Yubico's "YubiKey Hardware
//! FIDO2 AAGUIDs" support article. Other authenticators are admitted per run
//! with `rmm-sign sign --type techlist --allow-aaguid HEX`.

/// AAGUIDs of FIDO-certified YubiKey 5 series authenticators.
pub const YUBIKEY_5_AAGUIDS: &[[u8; 16]] = &[
    // YubiKey 5 CCN Series with NFC, firmware 5.7.4 (3aa78eb1-ddd8-46a8-a821-8f8ec57a7bd5)
    [
        0x3a, 0xa7, 0x8e, 0xb1, 0xdd, 0xd8, 0x46, 0xa8, 0xa8, 0x21, 0x8f, 0x8e, 0xc5, 0x7a, 0x7b,
        0xd5,
    ],
    // YubiKey 5 CCN Series with NFC (Consumer Profile), firmware 5.8.0 (eb7ef748-cbe0-4b40-b8f6-07bd2d592d35)
    [
        0xeb, 0x7e, 0xf7, 0x48, 0xcb, 0xe0, 0x4b, 0x40, 0xb8, 0xf6, 0x07, 0xbd, 0x2d, 0x59, 0x2d,
        0x35,
    ],
    // YubiKey 5 CCN Series with NFC (Enterprise Profile), firmware 5.7.4 (4fc84f16-2545-4e53-b8fc-7bf4d7282a10)
    [
        0x4f, 0xc8, 0x4f, 0x16, 0x25, 0x45, 0x4e, 0x53, 0xb8, 0xfc, 0x7b, 0xf4, 0xd7, 0x28, 0x2a,
        0x10,
    ],
    // YubiKey 5 CCN Series with NFC (Enterprise Profile), firmware 5.8.0 (3ec9c8d3-a5a7-415b-a7b5-f1d606368d3f)
    [
        0x3e, 0xc9, 0xc8, 0xd3, 0xa5, 0xa7, 0x41, 0x5b, 0xa7, 0xb5, 0xf1, 0xd6, 0x06, 0x36, 0x8d,
        0x3f,
    ],
    // YubiKey 5 FIPS Series, firmware 5.4.2 (73bb0cd4-e502-49b8-9c6f-b59445bf720b)
    [
        0x73, 0xbb, 0x0c, 0xd4, 0xe5, 0x02, 0x49, 0xb8, 0x9c, 0x6f, 0xb5, 0x94, 0x45, 0xbf, 0x72,
        0x0b,
    ],
    // YubiKey 5 FIPS Series, firmware 5.7.4 (57f7de54-c807-4eab-b1c6-1c9be7984e92)
    [
        0x57, 0xf7, 0xde, 0x54, 0xc8, 0x07, 0x4e, 0xab, 0xb1, 0xc6, 0x1c, 0x9b, 0xe7, 0x98, 0x4e,
        0x92,
    ],
    // YubiKey 5 FIPS Series (Enterprise Profile), firmware 5.7.4 (905b4cb4-ed6f-4da9-92fc-45e0d4e9b5c7)
    [
        0x90, 0x5b, 0x4c, 0xb4, 0xed, 0x6f, 0x4d, 0xa9, 0x92, 0xfc, 0x45, 0xe0, 0xd4, 0xe9, 0xb5,
        0xc7,
    ],
    // YubiKey 5 FIPS Series with Lightning, firmware 5.4.2 (85203421-48f9-4355-9bc8-8a53846e5083)
    [
        0x85, 0x20, 0x34, 0x21, 0x48, 0xf9, 0x43, 0x55, 0x9b, 0xc8, 0x8a, 0x53, 0x84, 0x6e, 0x50,
        0x83,
    ],
    // YubiKey 5 FIPS Series with Lightning, firmware 5.7.4 (7b96457d-e3cd-432b-9ceb-c9fdd7ef7432)
    [
        0x7b, 0x96, 0x45, 0x7d, 0xe3, 0xcd, 0x43, 0x2b, 0x9c, 0xeb, 0xc9, 0xfd, 0xd7, 0xef, 0x74,
        0x32,
    ],
    // YubiKey 5 FIPS Series with Lightning (Enterprise Profile), firmware 5.7.4 (3a662962-c6d4-4023-bebb-98ae92e78e20)
    [
        0x3a, 0x66, 0x29, 0x62, 0xc6, 0xd4, 0x40, 0x23, 0xbe, 0xbb, 0x98, 0xae, 0x92, 0xe7, 0x8e,
        0x20,
    ],
    // YubiKey 5 FIPS Series with NFC, firmware 5.4.2 (c1f9a0bc-1dd2-404a-b27f-8e29047a43fd)
    [
        0xc1, 0xf9, 0xa0, 0xbc, 0x1d, 0xd2, 0x40, 0x4a, 0xb2, 0x7f, 0x8e, 0x29, 0x04, 0x7a, 0x43,
        0xfd,
    ],
    // YubiKey 5 FIPS Series with NFC, firmware 5.7.4 (fcc0118f-cd45-435b-8da1-9782b2da0715)
    [
        0xfc, 0xc0, 0x11, 0x8f, 0xcd, 0x45, 0x43, 0x5b, 0x8d, 0xa1, 0x97, 0x82, 0xb2, 0xda, 0x07,
        0x15,
    ],
    // YubiKey 5 FIPS Series with NFC (Enterprise Profile), firmware 5.7.4 (79f3c8ba-9e35-484b-8f47-53a5a0f5c630)
    [
        0x79, 0xf3, 0xc8, 0xba, 0x9e, 0x35, 0x48, 0x4b, 0x8f, 0x47, 0x53, 0xa5, 0xa0, 0xf5, 0xc6,
        0x30,
    ],
    // YubiKey 5 Series, firmware 0.195.180 (cb69481e-8ff7-4039-93ec-0a2729a154a8)
    [
        0xcb, 0x69, 0x48, 0x1e, 0x8f, 0xf7, 0x40, 0x39, 0x93, 0xec, 0x0a, 0x27, 0x29, 0xa1, 0x54,
        0xa8,
    ],
    // YubiKey 5 Series, firmware 5.4.2 (ee882879-721c-4913-9775-3dfcce97072a)
    [
        0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13, 0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07,
        0x2a,
    ],
    // YubiKey 5 Series, firmware 5.7.1 (19083c3d-8383-4b18-bc03-8f1c9ab2fd1b)
    [
        0x19, 0x08, 0x3c, 0x3d, 0x83, 0x83, 0x4b, 0x18, 0xbc, 0x03, 0x8f, 0x1c, 0x9a, 0xb2, 0xfd,
        0x1b,
    ],
    // YubiKey 5 Series, firmware 5.7.4 (ff4dac45-ede8-4ec2-aced-cf66103f4335)
    [
        0xff, 0x4d, 0xac, 0x45, 0xed, 0xe8, 0x4e, 0xc2, 0xac, 0xed, 0xcf, 0x66, 0x10, 0x3f, 0x43,
        0x35,
    ],
    // YubiKey 5 Series (Consumer Profile), firmware 5.8.0 (0a357157-9b18-4c8a-920e-d156e972b2f8)
    [
        0x0a, 0x35, 0x71, 0x57, 0x9b, 0x18, 0x4c, 0x8a, 0x92, 0x0e, 0xd1, 0x56, 0xe9, 0x72, 0xb2,
        0xf8,
    ],
    // YubiKey 5 Series (Enterprise Profile), firmware 5.7.1 (20ac7a17-c814-4833-93fe-539f0d5e3389)
    [
        0x20, 0xac, 0x7a, 0x17, 0xc8, 0x14, 0x48, 0x33, 0x93, 0xfe, 0x53, 0x9f, 0x0d, 0x5e, 0x33,
        0x89,
    ],
    // YubiKey 5 Series (Enterprise Profile), firmware 5.7.4 (4599062e-6926-4fe7-9566-9e8fb1aedaa0)
    [
        0x45, 0x99, 0x06, 0x2e, 0x69, 0x26, 0x4f, 0xe7, 0x95, 0x66, 0x9e, 0x8f, 0xb1, 0xae, 0xda,
        0xa0,
    ],
    // YubiKey 5 Series (Enterprise Profile), firmware 5.8.0 (524de2de-982f-49b4-a769-2b5e3b73ad79)
    [
        0x52, 0x4d, 0xe2, 0xde, 0x98, 0x2f, 0x49, 0xb4, 0xa7, 0x69, 0x2b, 0x5e, 0x3b, 0x73, 0xad,
        0x79,
    ],
    // YubiKey 5 Series with Lightning, firmware 5.4.2 (c5ef55ff-ad9a-4b9f-b580-adebafe026d0)
    [
        0xc5, 0xef, 0x55, 0xff, 0xad, 0x9a, 0x4b, 0x9f, 0xb5, 0x80, 0xad, 0xeb, 0xaf, 0xe0, 0x26,
        0xd0,
    ],
    // YubiKey 5 Series with Lightning, firmware 5.7.1 (a02167b9-ae71-4ac7-9a07-06432ebb6f1c)
    [
        0xa0, 0x21, 0x67, 0xb9, 0xae, 0x71, 0x4a, 0xc7, 0x9a, 0x07, 0x06, 0x43, 0x2e, 0xbb, 0x6f,
        0x1c,
    ],
    // YubiKey 5 Series with Lightning, firmware 5.7.4 (24673149-6c86-42e7-98d9-433fb5b73296)
    [
        0x24, 0x67, 0x31, 0x49, 0x6c, 0x86, 0x42, 0xe7, 0x98, 0xd9, 0x43, 0x3f, 0xb5, 0xb7, 0x32,
        0x96,
    ],
    // YubiKey 5 Series with Lightning (Consumer Profile), firmware 5.8.0 (03012cb7-4fb2-42e7-9e8d-a81f10e2a5e9)
    [
        0x03, 0x01, 0x2c, 0xb7, 0x4f, 0xb2, 0x42, 0xe7, 0x9e, 0x8d, 0xa8, 0x1f, 0x10, 0xe2, 0xa5,
        0xe9,
    ],
    // YubiKey 5 Series with Lightning (Enterprise Profile), firmware 5.7.1 (b90e7dc1-316e-4fee-a25a-56a666a670fe)
    [
        0xb9, 0x0e, 0x7d, 0xc1, 0x31, 0x6e, 0x4f, 0xee, 0xa2, 0x5a, 0x56, 0xa6, 0x66, 0xa6, 0x70,
        0xfe,
    ],
    // YubiKey 5 Series with Lightning (Enterprise Profile), firmware 5.7.4 (3b24bf49-1d45-4484-a917-13175df0867b)
    [
        0x3b, 0x24, 0xbf, 0x49, 0x1d, 0x45, 0x44, 0x84, 0xa9, 0x17, 0x13, 0x17, 0x5d, 0xf0, 0x86,
        0x7b,
    ],
    // YubiKey 5 Series with Lightning (Enterprise Profile), firmware 5.8.0 (c3479970-e58a-4f70-836f-853bf42fb063)
    [
        0xc3, 0x47, 0x99, 0x70, 0xe5, 0x8a, 0x4f, 0x70, 0x83, 0x6f, 0x85, 0x3b, 0xf4, 0x2f, 0xb0,
        0x63,
    ],
    // YubiKey 5 Series with NFC, firmware 0.195.180 (fa2b99dc-9e39-4257-8f92-4a30d23c4118)
    [
        0xfa, 0x2b, 0x99, 0xdc, 0x9e, 0x39, 0x42, 0x57, 0x8f, 0x92, 0x4a, 0x30, 0xd2, 0x3c, 0x41,
        0x18,
    ],
    // YubiKey 5 Series with NFC, firmware 5.4.2 (2fc0579f-8113-47ea-b116-bb5a8db9202a)
    [
        0x2f, 0xc0, 0x57, 0x9f, 0x81, 0x13, 0x47, 0xea, 0xb1, 0x16, 0xbb, 0x5a, 0x8d, 0xb9, 0x20,
        0x2a,
    ],
    // YubiKey 5 Series with NFC, firmware 5.7.1 (a25342c0-3cdc-4414-8e46-f4807fca511c)
    [
        0xa2, 0x53, 0x42, 0xc0, 0x3c, 0xdc, 0x44, 0x14, 0x8e, 0x46, 0xf4, 0x80, 0x7f, 0xca, 0x51,
        0x1c,
    ],
    // YubiKey 5 Series with NFC, firmware 5.7.4 (d7781e5d-e353-46aa-afe2-3ca49f13332a)
    [
        0xd7, 0x78, 0x1e, 0x5d, 0xe3, 0x53, 0x46, 0xaa, 0xaf, 0xe2, 0x3c, 0xa4, 0x9f, 0x13, 0x33,
        0x2a,
    ],
    // YubiKey 5 Series with NFC (Consumer Profile), firmware 5.8.0 (f4ce5fc0-57d3-46f5-a736-efb7d5bc63b5)
    [
        0xf4, 0xce, 0x5f, 0xc0, 0x57, 0xd3, 0x46, 0xf5, 0xa7, 0x36, 0xef, 0xb7, 0xd5, 0xbc, 0x63,
        0xb5,
    ],
    // YubiKey 5 Series with NFC (Consumer Profile) KVZR57-2, firmware 5.8.0 (7dab85a5-d16d-4eaf-a7ef-4c1385b151c5)
    [
        0x7d, 0xab, 0x85, 0xa5, 0xd1, 0x6d, 0x4e, 0xaf, 0xa7, 0xef, 0x4c, 0x13, 0x85, 0xb1, 0x51,
        0xc5,
    ],
    // YubiKey 5 Series with NFC (Enterprise Profile), firmware 5.7.1 (1ac71f64-468d-4fe0-bef1-0e5f2f551f18)
    [
        0x1a, 0xc7, 0x1f, 0x64, 0x46, 0x8d, 0x4f, 0xe0, 0xbe, 0xf1, 0x0e, 0x5f, 0x2f, 0x55, 0x1f,
        0x18,
    ],
    // YubiKey 5 Series with NFC (Enterprise Profile), firmware 5.7.4 (6ab56fad-881f-4a43-acb2-0be065924522)
    [
        0x6a, 0xb5, 0x6f, 0xad, 0x88, 0x1f, 0x4a, 0x43, 0xac, 0xb2, 0x0b, 0xe0, 0x65, 0x92, 0x45,
        0x22,
    ],
    // YubiKey 5 Series with NFC (Enterprise Profile), firmware 5.8.0 (41e39911-c669-4811-b860-c6ad0b411b96)
    [
        0x41, 0xe3, 0x99, 0x11, 0xc6, 0x69, 0x48, 0x11, 0xb8, 0x60, 0xc6, 0xad, 0x0b, 0x41, 0x1b,
        0x96,
    ],
    // YubiKey 5 Series with NFC - Enhanced PIN, firmware 5.7.4 (662ef48a-95e2-4aaa-a6c1-5b9c40375824)
    [
        0x66, 0x2e, 0xf4, 0x8a, 0x95, 0xe2, 0x4a, 0xaa, 0xa6, 0xc1, 0x5b, 0x9c, 0x40, 0x37, 0x58,
        0x24,
    ],
    // YubiKey 5 Series with NFC - Enhanced PIN (Enterprise Profile), firmware 5.7.4 (b2c1a50b-dad8-4dc7-ba4d-0ce9597904bc)
    [
        0xb2, 0xc1, 0xa5, 0x0b, 0xda, 0xd8, 0x4d, 0xc7, 0xba, 0x4d, 0x0c, 0xe9, 0x59, 0x79, 0x04,
        0xbc,
    ],
    // YubiKey 5 Series with NFC Enhanced PIN (Consumer Profile), firmware 5.8.0 (0ebd9f2c-f685-441c-8c3e-a02a234a840a)
    [
        0x0e, 0xbd, 0x9f, 0x2c, 0xf6, 0x85, 0x44, 0x1c, 0x8c, 0x3e, 0xa0, 0x2a, 0x23, 0x4a, 0x84,
        0x0a,
    ],
    // YubiKey 5 Series with NFC Enhanced PIN (Enterprise Profile), firmware 5.8.0 (9a3f2abd-a73d-439c-9ee7-1b53a857eaa7)
    [
        0x9a, 0x3f, 0x2a, 0xbd, 0xa7, 0x3d, 0x43, 0x9c, 0x9e, 0xe7, 0x1b, 0x53, 0xa8, 0x57, 0xea,
        0xa7,
    ],
    // YubiKey 5 Series with NFC KVZR57, firmware 5.7.4 (9eb7eabc-9db5-49a1-b6c3-555a802093f4)
    [
        0x9e, 0xb7, 0xea, 0xbc, 0x9d, 0xb5, 0x49, 0xa1, 0xb6, 0xc3, 0x55, 0x5a, 0x80, 0x20, 0x93,
        0xf4,
    ],
];

/// Parse an AAGUID given as 32 hex digits, optionally in 8-4-4-4-12 form.
pub fn parse(s: &str) -> Result<[u8; 16], String> {
    let t = s.trim();
    let dashed = t.len() == 36
        && [8, 13, 18, 23]
            .iter()
            .all(|&i| t.as_bytes().get(i) == Some(&b'-'));
    let hex: String = if dashed {
        t.chars().filter(|c| *c != '-').collect()
    } else {
        t.to_owned()
    };
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "AAGUID {s:?} must be 32 hex digits (16 bytes), optionally dashed"
        ));
    }
    let raw = hex::decode(&hex).map_err(|e| format!("AAGUID {s:?}: {e}"))?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Lowercase dashed form of an AAGUID.
pub fn format(a: &[u8]) -> String {
    let h = hex::encode(a);
    if h.len() != 32 {
        return h;
    }
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// Whether `aaguid` is a compiled YubiKey 5 AAGUID or in `extra`.
pub fn is_allowed(aaguid: &[u8; 16], extra: &[[u8; 16]]) -> bool {
    YUBIKEY_5_AAGUIDS.contains(aaguid) || extra.contains(aaguid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn list_is_unique_and_nonzero() {
        let mut seen = std::collections::BTreeSet::new();
        for a in YUBIKEY_5_AAGUIDS {
            assert_ne!(*a, [0u8; 16]);
            assert!(seen.insert(*a), "duplicate {}", format(a));
        }
        assert!(YUBIKEY_5_AAGUIDS.len() >= 20);
    }

    #[test]
    fn known_models_are_listed() {
        for s in [
            "cb69481e-8ff7-4039-93ec-0a2729a154a8", // YubiKey 5 (5.1)
            "ee882879-721c-4913-9775-3dfcce97072a", // YubiKey 5 (5.2/5.4)
            "fa2b99dc-9e39-4257-8f92-4a30d23c4118", // YubiKey 5 NFC (5.1)
            "2fc0579f-8113-47ea-b116-bb5a8db9202a", // YubiKey 5 NFC (5.2/5.4)
            "c5ef55ff-ad9a-4b9f-b580-adebafe026d0", // YubiKey 5Ci
            "73bb0cd4-e502-49b8-9c6f-b59445bf720b", // YubiKey 5 FIPS
            "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd", // YubiKey 5 NFC FIPS
            "85203421-48f9-4355-9bc8-8a53846e5083", // YubiKey 5Ci FIPS
            "a25342c0-3cdc-4414-8e46-f4807fca511c", // YubiKey 5 NFC (5.7)
            "19083c3d-8383-4b18-bc03-8f1c9ab2fd1b", // YubiKey 5 (5.7)
        ] {
            assert!(is_allowed(&parse(s).unwrap(), &[]), "{s}");
        }
    }

    #[test]
    fn parse_forms() {
        let a = parse("EE882879721C491397753DFCCE97072A").unwrap();
        assert_eq!(a, parse("ee882879-721c-4913-9775-3dfcce97072a").unwrap());
        assert_eq!(format(&a), "ee882879-721c-4913-9775-3dfcce97072a");
        for bad in [
            "",
            "ee88",
            "zz882879721c491397753dfcce97072a",
            "ee882879-721c49-13-9775-3dfcce97072a",
            "ee882879721c491397753dfcce97072a00",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
