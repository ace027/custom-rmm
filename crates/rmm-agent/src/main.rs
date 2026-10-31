//! Endpoint agent binary (skeleton).

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("rmm-agent {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    println!("rmm-agent: {}", rmm_agent_core::identity());
}
