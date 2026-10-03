// The safe version of vulnerable/main.rs. ThreadAI must report nothing here.
use anyhow::{Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args[1].parse().context("port must be a number")?;

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    Command::new("tar").args(["xf", &args[2]]).status()?;

    let name = &args[3];
    let rows = sqlx::query("SELECT * FROM users WHERE name = ?").bind(name);

    let username = &args[4];
    println!("user {} logged in on port {}", username, port);

    fs::set_permissions("vault.dat", fs::Permissions::from_mode(0o600))?;

    let _ = (nonce, rows);
    Ok(())
}
