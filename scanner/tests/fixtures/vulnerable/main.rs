// Intentionally vulnerable sample for ThreadAI tests. NEVER ship this.
// Each `expect:` comment names the rule(s) that must fire on the NEXT line.
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

// expect: TAI-RS-005
const KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // expect: TAI-RS-002
    let port: u16 = args[1].parse().unwrap();

    let ptr = &port as *const u16;
    // expect: TAI-RS-001
    let v = unsafe { *ptr };

    // expect: TAI-RS-003
    let session_token = SmallRng::seed_from_u64(42).next_u64();

    // expect: TAI-RS-004
    Command::new("sh").arg("-c").arg(format!("tar xf {}", args[2])).status().ok();

    let client = reqwest::blocking::Client::builder()
        // expect: TAI-CORE-008
        .danger_accept_invalid_certs(true)
        .build();

    let name = &args[3];
    // expect: TAI-CORE-010
    let q = format!("SELECT * FROM users WHERE name = '{}'", name);

    let password = &args[4];
    // expect: TAI-CORE-013
    println!("debug: password={}", password);

    // expect: TAI-CORE-012
    fs::set_permissions("vault.dat", fs::Permissions::from_mode(0o777)).ok();

    let _ = (v, session_token, client, q, KEY);
}
