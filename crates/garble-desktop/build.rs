use tauri_build::{AppManifest, Attributes};

// Listing the commands here is what makes the capability file an allowlist: a command
// that isn't in this list can't be invoked, and one that is still needs its
// `allow-*` permission in capabilities/main.json.
const COMMANDS: &[&str] = &[
    "list_rooms",
    "open_room",
    "create_room",
    "validate_marking",
    "send",
    "banner",
    "add_member",
    "remove_member",
    "denial",
    "watermark",
];

fn main() {
    tauri_build::try_build(Attributes::new().app_manifest(AppManifest::new().commands(COMMANDS)))
        .expect("tauri build");
}
