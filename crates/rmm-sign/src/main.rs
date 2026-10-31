//! Offline signing CLI (skeleton).

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("rmm-sign {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    println!("rmm-sign: signing={}", rmm_trust::sign::SIGNING_ENABLED);
}
