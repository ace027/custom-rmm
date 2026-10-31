//! Offline signing CLI (skeleton).

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("rmm-sign {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    println!(
        "rmm-sign: sign marker length={}",
        rmm_trust::sign::SIGN_MODULE_MARKER.len()
    );
}
