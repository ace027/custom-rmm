use rmm_proto::shell::{Bytes, MAX_CHUNK, ShellCtl, ShellIn, ShellOut};
use rmm_proto::subjects;

#[test]
fn out_round_trips() {
    for m in [
        ShellOut::Data {
            seq: 7,
            data: Bytes(b"hi\r\n".to_vec()),
        },
        ShellOut::Data {
            seq: 0,
            data: Bytes(vec![]),
        },
        ShellOut::Exit { code: -1 },
        ShellOut::Exit { code: 3 },
        ShellOut::Closed {
            reason: "timeout".into(),
        },
    ] {
        let b = m.to_cbor().expect("enc");
        assert_eq!(ShellOut::from_cbor(&b).expect("dec"), m);
    }
}

#[test]
fn in_round_trips() {
    for m in [
        ShellIn::Data {
            data: Bytes(b"ls\n".to_vec()),
        },
        ShellIn::Resize {
            cols: 120,
            rows: 40,
        },
    ] {
        let b = m.to_cbor().expect("enc");
        assert_eq!(ShellIn::from_cbor(&b).expect("dec"), m);
    }
}

#[test]
fn ctl_round_trips() {
    for m in [
        ShellCtl::Ack { seq: 99 },
        ShellCtl::Window { bytes: 262_144 },
        ShellCtl::Ping,
        ShellCtl::Close,
    ] {
        let b = m.to_cbor().expect("enc");
        assert_eq!(ShellCtl::from_cbor(&b).expect("dec"), m);
    }
}

#[test]
fn data_is_a_cbor_byte_string() {
    let b = ShellIn::Data {
        data: Bytes(vec![1, 2, 3]),
    }
    .to_cbor()
    .expect("enc");
    // map(1) "Data" -> map(1) "data" -> bytes(3)
    assert!(b.windows(4).any(|w| w == [0x43, 1, 2, 3]));
}

#[test]
fn rejects_trailing_bytes() {
    let mut b = ShellCtl::Ping.to_cbor().expect("enc");
    b.push(0);
    assert!(ShellCtl::from_cbor(&b).is_err());
    let mut b = ShellOut::Exit { code: 0 }.to_cbor().expect("enc");
    b.push(0);
    assert!(ShellOut::from_cbor(&b).is_err());
}

#[test]
fn rejects_garbage_and_unknown_variants() {
    assert!(ShellCtl::from_cbor(&[]).is_err());
    assert!(ShellCtl::from_cbor(&[0xff]).is_err());
    assert!(ShellIn::from_cbor(&ShellCtl::Close.to_cbor().expect("enc")).is_err());
}

#[test]
fn oversize_chunk_rejected() {
    let ok = ShellOut::Data {
        seq: 1,
        data: Bytes(vec![0; MAX_CHUNK]),
    };
    let b = ok.to_cbor().expect("max chunk is fine");
    assert_eq!(ShellOut::from_cbor(&b).expect("dec"), ok);

    let big = ShellOut::Data {
        seq: 1,
        data: Bytes(vec![0; MAX_CHUNK + 1]),
    };
    assert!(big.to_cbor().is_err());
    // Bypass the encoder check to prove the decoder enforces it too.
    let raw = rmm_proto::canonical::to_canonical_vec(&big).expect("raw");
    assert!(ShellOut::from_cbor(&raw).is_err());

    let big_in = ShellIn::Data {
        data: Bytes(vec![0; MAX_CHUNK + 1]),
    };
    let raw = rmm_proto::canonical::to_canonical_vec(&big_in).expect("raw");
    assert!(ShellIn::from_cbor(&raw).is_err());
}

#[test]
fn subject_strings() {
    let sid = subjects::sid_from_grant_id(&[0xde, 0xad, 0x01, 0xff]);
    assert_eq!(sid, "dead01ff");
    assert_eq!(subjects::shell_in("a1", &sid), "shell.a1.dead01ff.in");
    assert_eq!(subjects::shell_out("a1", &sid), "shell.a1.dead01ff.out");
    assert_eq!(subjects::shell_ctl("a1", &sid), "shell.a1.dead01ff.ctl");
}
