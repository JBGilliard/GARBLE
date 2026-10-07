//! Tauri commands: the whole surface the webview can reach. Each is a one-liner over
//! `Core`; the names must match `COMMANDS` in build.rs and the permissions in
//! capabilities/main.json, or the call is refused.
//!
//! Async so they run off the main thread: a command can wait on the DS, and the UI
//! thread mustn't.

use tauri::{AppHandle, State};

use crate::console::Core;
use crate::events::UiEvent;
use crate::views::{
    DenialDetail, MarkingCheck, MarkingView, MessageView, MsgId, Page, RoomSummary, UiError,
    WatermarkSpec,
};

#[tauri::command]
pub async fn list_rooms(core: State<'_, Core>) -> Result<Vec<RoomSummary>, UiError> {
    core.list_rooms()
}

#[tauri::command]
pub async fn open_room(
    core: State<'_, Core>,
    room: String,
    anchor: Option<u64>,
    limit: usize,
) -> Result<Page<MessageView>, UiError> {
    core.open_room(&room, anchor, limit)
}

#[tauri::command]
pub async fn create_room(
    app: AppHandle,
    core: State<'_, Core>,
    room: String,
    ceiling: String,
) -> Result<String, UiError> {
    let room = core.create_room(&room, &ceiling)?;
    UiEvent::RoomChanged {
        room: room.clone(),
        change: "joined",
    }
    .emit(&app);
    Ok(room)
}

#[tauri::command]
pub async fn validate_marking(
    core: State<'_, Core>,
    room: String,
    text: String,
) -> Result<MarkingCheck, UiError> {
    core.validate_marking(&room, &text)
}

#[tauri::command]
pub async fn send(
    app: AppHandle,
    core: State<'_, Core>,
    room: String,
    marking: String,
    body: String,
) -> Result<MsgId, UiError> {
    let sent = core.send(&room, &marking, &body)?;
    UiEvent::MessagesAppended {
        room,
        items: vec![sent.view],
    }
    .emit(&app);
    Ok(sent.id)
}

#[tauri::command]
pub async fn banner(core: State<'_, Core>, visible: Vec<MsgId>) -> Result<MarkingView, UiError> {
    core.banner(&visible)
}

#[tauri::command]
pub async fn add_member(
    app: AppHandle,
    core: State<'_, Core>,
    room: String,
    user: String,
) -> Result<(), UiError> {
    let view = core.add_member(&room, &user)?;
    membership_changed(&app, room, view);
    Ok(())
}

#[tauri::command]
pub async fn remove_member(
    app: AppHandle,
    core: State<'_, Core>,
    room: String,
    user: String,
) -> Result<(), UiError> {
    let view = core.remove_member(&room, &user)?;
    membership_changed(&app, room, view);
    Ok(())
}

fn membership_changed(app: &AppHandle, room: String, notice: MessageView) {
    UiEvent::MessagesAppended {
        room: room.clone(),
        items: vec![notice],
    }
    .emit(app);
    UiEvent::RoomChanged {
        room,
        change: "membership",
    }
    .emit(app);
}

#[tauri::command]
pub async fn denial(core: State<'_, Core>, audit_ref: String) -> Result<DenialDetail, UiError> {
    core.denial(&audit_ref)
}

#[tauri::command]
pub async fn watermark(core: State<'_, Core>) -> Result<WatermarkSpec, UiError> {
    core.watermark()
}
