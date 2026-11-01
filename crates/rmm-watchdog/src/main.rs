//! Watchdog and updater (skeleton). Sync std only, no async runtime.

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("rmm-watchdog {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    println!(
        "rmm-watchdog: protocol={}",
        rmm_trust::verify::supported_protocol()
    );
}
