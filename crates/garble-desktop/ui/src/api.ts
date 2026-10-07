// The whole surface to the Rust core. Mirrors crates/garble-desktop/src/views.rs; if one
// changes, so does the other. Nothing here knows about keys, MLS or credentials.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export type MarkingView = {
  portion: string;
  banner: string;
  level: "U" | "C" | "S" | "TS";
  colors: { bg: string; fg: string };
};

export type MsgId = { room: string; seq: number };

export type MessageView = {
  id: MsgId;
  kind: "message" | "ack" | "quarantined" | "notice";
  sender: string;
  mine: boolean;
  marking: MarkingView | null;
  text: string;
  forwarded_from: string | null;
  of: number | null;
};

export type Page<T> = { items: T[]; older: number | null };

export type RoomSummary = {
  room: string;
  ceiling: MarkingView;
  members: string[];
  stewards: string[];
  unread: number;
  last_seq: number;
  held: boolean;
};

export type Verdict =
  | { result: "permit" }
  | { result: "deny"; code: string; reason: string }
  | { result: "invalid"; code: string; reason: string };

export type MarkingCheck = { parsed: MarkingView | null; decision: Verdict };

export type LogLine = {
  id: number;
  at: number;
  actor: string;
  room: string;
  event: string;
  decision: string;
  code: string | null;
  detail: string;
  marking: string;
};

export type DenialDetail = {
  audit: string;
  entry: LogLine | null;
  inclusion: { status: "proven"; size: number; root: string } | { status: "withheld" };
};

export type Denial = {
  room: string;
  by: string;
  code: string | null;
  reason: string;
  audit: string | null;
};

export type CredentialState =
  | { state: "active"; until: number }
  | { state: "expired"; since: number }
  | { state: "not_enrolled" };

export type UiError =
  | { kind: "denied"; by: string; code: string; reason: string; audit: string }
  | { kind: "integrity"; reason: string }
  | { kind: "failed"; message: string };

/** Anything a command rejects with, as a `UiError`. ACL refusals arrive as bare strings. */
export function asUiError(e: unknown): UiError {
  if (typeof e === "object" && e !== null && "kind" in e) return e as UiError;
  return { kind: "failed", message: String(e) };
}

export const api = {
  listRooms: () => invoke<RoomSummary[]>("list_rooms"),
  openRoom: (room: string, anchor: number | null, limit: number) =>
    invoke<Page<MessageView>>("open_room", { room, anchor, limit }),
  createRoom: (room: string, ceiling: string) => invoke<string>("create_room", { room, ceiling }),
  validateMarking: (room: string, text: string) =>
    invoke<MarkingCheck>("validate_marking", { room, text }),
  send: (room: string, marking: string, body: string) =>
    invoke<MsgId>("send", { room, marking, body }),
  banner: (visible: MsgId[]) => invoke<MarkingView>("banner", { visible }),
  addMember: (room: string, user: string) => invoke<void>("add_member", { room, user }),
  removeMember: (room: string, user: string) => invoke<void>("remove_member", { room, user }),
  denial: (auditRef: string) => invoke<DenialDetail>("denial", { auditRef }),
  watermark: () => invoke<{ text: string; seed: string }>("watermark"),
};

export type CoreEvents = {
  messages_appended: { room: string; items: MessageView[] };
  room_changed: { room: string; change: string };
  denial: Denial;
  credential_state: CredentialState;
  integrity_alert: { room: string | null; reason: string };
  connection: { ok: boolean; message: string | null };
};

export function on<K extends keyof CoreEvents>(name: K, f: (p: CoreEvents[K]) => void) {
  return listen<CoreEvents[K]>(name, (e) => f(e.payload));
}
