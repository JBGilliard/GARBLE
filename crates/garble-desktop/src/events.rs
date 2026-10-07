//! Core → webview events (architecture §7.1).

use serde_json::json;
use tauri::{AppHandle, Emitter, Runtime};

use crate::views::{CredentialState, Denial, MessageView};

pub enum UiEvent {
    MessagesAppended {
        room: String,
        items: Vec<MessageView>,
    },
    /// `joined`, `membership`, `ceiling`, `held` or `purged`. The webview re-reads.
    RoomChanged {
        room: String,
        change: &'static str,
    },
    Denial(Denial),
    CredentialState(CredentialState),
    /// `room` is `None` for the log, `Some` for a frozen room.
    IntegrityAlert {
        room: Option<String>,
        reason: String,
    },
    /// Not in §7.1, but a silent DS outage looks exactly like a quiet night.
    Connection {
        ok: bool,
        message: Option<String>,
    },
}

impl UiEvent {
    pub fn emit<R: Runtime>(&self, app: &AppHandle<R>) {
        let sent = match self {
            Self::MessagesAppended { room, items } => {
                app.emit("messages_appended", json!({ "room": room, "items": items }))
            }
            Self::RoomChanged { room, change } => {
                app.emit("room_changed", json!({ "room": room, "change": change }))
            }
            Self::Denial(d) => app.emit("denial", d),
            Self::CredentialState(s) => app.emit("credential_state", s),
            Self::IntegrityAlert { room, reason } => {
                app.emit("integrity_alert", json!({ "room": room, "reason": reason }))
            }
            Self::Connection { ok, message } => {
                app.emit("connection", json!({ "ok": ok, "message": message }))
            }
        };
        if let Err(e) = sent {
            eprintln!("event not delivered: {e}");
        }
    }
}
