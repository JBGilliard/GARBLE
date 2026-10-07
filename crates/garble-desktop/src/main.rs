//! GARBLE desktop app (architecture §3, §7.1). The core in `console.rs` is the application;
//! the webview in `ui/` is a view over the commands in `commands.rs`.
//!
//! ponytail: the identity comes from a `garble-cli init`/`enroll` home dir
//! (`--home DIR` or `GARBLE_HOME`). Enrollment and credential refresh in the app, and a
//! WebSocket instead of polling, come later.

mod commands;
mod console;
mod events;
mod views;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use client::Client;
use tauri::Manager;

use crate::console::Core;

const SYNC_EVERY: Duration = Duration::from_secs(2);

fn home() -> Result<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--home" {
            return args.next().map(PathBuf::from).context("--home needs a DIR");
        }
    }
    std::env::var_os("GARBLE_HOME")
        .map(PathBuf::from)
        .context("usage: garble-desktop --home DIR   (or set GARBLE_HOME)")
}

fn run() -> Result<()> {
    let home = home()?;
    let client = Client::open(&home)?;
    let core = Core::new(client)?;
    tauri::Builder::default()
        .manage(core)
        .invoke_handler(tauri::generate_handler![
            commands::list_rooms,
            commands::open_room,
            commands::create_room,
            commands::validate_marking,
            commands::send,
            commands::banner,
            commands::add_member,
            commands::remove_member,
            commands::denial,
            commands::watermark,
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    for e in handle.state::<Core>().tick() {
                        e.emit(&handle);
                    }
                    std::thread::sleep(SYNC_EVERY);
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .context("tauri")
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
