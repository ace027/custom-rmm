//! Session helper (skeleton).

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("rmm-session {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    println!("rmm-session: protocol={}", rmm_proto::PROTOCOL_VERSION);
}
