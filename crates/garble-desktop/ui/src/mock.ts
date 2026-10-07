// Dev only (never in the build): a fake core, so the UI can be worked on in a browser
// with `npm run dev`. Imitates the shapes in api.ts, not the policy.
import type { MarkingView, MessageView, RoomSummary } from "./api";

const LEVELS = ["U", "C", "S", "TS"] as const;
const NAMES = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP SECRET"];
const COLORS = [
  { bg: "#007a33", fg: "#ffffff" },
  { bg: "#0033a0", fg: "#ffffff" },
  { bg: "#c8102e", fg: "#ffffff" },
  { bg: "#ff8c00", fg: "#000000" },
];

const rank = (p: string) => LEVELS.indexOf(p.split("//")[0] as (typeof LEVELS)[number]);
const valid = (p: string) => rank(p) >= 0 && /^[A-Z]+(\/\/[A-Z/,-]+)*$/.test(p);
function view(p: string): MarkingView {
  const r = rank(p);
  const sci = p.includes("SI") || p.includes("TK");
  const colors = r === 3 && sci ? { bg: "#f7ea48", fg: "#000000" } : COLORS[r]!;
  return {
    portion: p,
    banner: [NAMES[r], ...p.split("//").slice(1)].join("//"),
    level: LEVELS[r]!,
    colors,
  };
}

const msg = (room: string, seq: number, kind: MessageView["kind"], sender: string, p: string | null, text: string, extra: Partial<MessageView> = {}): MessageView => ({
  id: { room, seq },
  kind,
  sender,
  mine: sender === "alice",
  marking: p ? view(p) : null,
  text,
  forwarded_from: null,
  of: null,
  ...extra,
});

const feeds: Record<string, MessageView[]> = {
  ops: [
    msg("ops", 2, "notice", "alice", null, "you added bob"),
    msg("ops", 3, "message", "bob", "TS//SI//NF", "Package is staged. Awaiting go."),
    msg("ops", 4, "message", "alice", "S//NF", "Copy. Holding until 2200Z."),
    msg("ops", 5, "ack", "bob", "S//NF", "", { of: 4 }),
    msg("ops", 6, "quarantined", "mallory", null, "S//NF is above this sender's clearance"),
    msg("ops", 7, "message", "bob", "U", "Lunch is at noon.\nBring your own."),
  ],
  watch: [msg("watch", 2, "message", "carol", "S//NF", "Quiet night.", { forwarded_from: "carol in ops" })],
};
const rooms: RoomSummary[] = [
  { room: "ops", ceiling: view("TS//SI//NF"), members: ["alice", "bob"], stewards: ["alice"], unread: 0, last_seq: 7, held: false },
  { room: "watch", ceiling: view("S//NF"), members: ["alice", "carol"], stewards: ["alice"], unread: 1, last_seq: 2, held: false },
];

const listeners = new Map<string, Array<(e: unknown) => void>>();
const callbacks = new Map<number, (e: unknown) => void>();
let ids = 1;
const emit = (event: string, payload: unknown) =>
  listeners.get(event)?.forEach((cb) => cb({ event, id: 0, payload }));

const denied = (reason: string) => ({ kind: "denied", by: "client", code: "P-004", reason, audit: "L-12" });
const ceilingOf = (room: string) => rooms.find((r) => r.room === room)!.ceiling.portion;

const handlers: Record<string, (a: any) => unknown> = {
  list_rooms: () => rooms,
  open_room: ({ room, anchor, limit }) => {
    const all = feeds[room] ?? [];
    const end = anchor === null ? all.length : all.filter((m) => m.id.seq < anchor).length;
    const start = Math.max(0, end - limit);
    return { items: all.slice(start, end), older: start > 0 ? all[start]!.id.seq : null };
  },
  create_room: ({ room, ceiling }) => {
    if (!valid(ceiling)) throw denied(`bad ceiling ${ceiling}`);
    rooms.push({ room, ceiling: view(ceiling), members: ["alice"], stewards: ["alice"], unread: 0, last_seq: 1, held: false });
    feeds[room] = [];
    return room;
  },
  validate_marking: ({ room, text }) => {
    if (!valid(text)) {
      return { parsed: null, decision: { result: "invalid", code: "M-003", reason: `unknown classification level '${text}'` } };
    }
    const parsed = view(text);
    return rank(text) > rank(ceilingOf(room))
      ? { parsed, decision: { result: "deny", code: "P-004", reason: "marking is above the room ceiling" } }
      : { parsed, decision: { result: "permit" } };
  },
  send: ({ room, marking, body }) => {
    if (rank(marking) > rank(ceilingOf(room))) throw denied("marking is above the room ceiling");
    const seq = (feeds[room]!.at(-1)?.id.seq ?? 1) + 1;
    const m = msg(room, seq, "message", "alice", marking, body);
    feeds[room]!.push(m);
    setTimeout(() => emit("messages_appended", { room, items: [m] }), 50);
    return m.id;
  },
  banner: ({ visible }) => {
    const top = Math.max(...visible.map((id: { room: string; seq: number }) => rank(feeds[id.room]!.find((m) => m.id.seq === id.seq)!.marking!.portion)));
    return view(LEVELS[top]!);
  },
  add_member: () => undefined,
  remove_member: () => undefined,
  denial: ({ auditRef }) => ({
    audit: auditRef,
    entry: { id: 12, at: Math.floor(Date.now() / 1000), actor: "alice", room: "ops", event: "send", decision: "deny", code: "P-004", detail: "marking above ceiling", marking: "TS//SI//NF" },
    inclusion: { status: "proven", size: 41, root: "9f2c1ab07d3e5566aa01b2c3d4e5f607" },
  }),
  watermark: () => ({ text: "alice · 3fa91c07", seed: "3fa91c07deadbeef" }),
  "plugin:event|listen": ({ event, handler }) => {
    const cb = callbacks.get(handler)!;
    listeners.set(event, [...(listeners.get(event) ?? []), cb]);
    return ids++;
  },
  "plugin:event|unlisten": () => undefined,
};

(window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {
  transformCallback: (cb: (e: unknown) => void) => {
    const id = ids++;
    callbacks.set(id, cb);
    return id;
  },
  invoke: async (cmd: string, args: unknown) => {
    const f = handlers[cmd];
    if (!f) throw `command ${cmd} not allowed`;
    return f(args);
  },
};

// Like the real core: state goes out every round, not once.
setInterval(() => {
  emit("connection", { ok: true, message: null });
  emit("credential_state", { state: "active", until: Math.floor(Date.now() / 1000) + 7200 });
}, 2000);
setTimeout(() => {
  const m = msg("ops", 8, "message", "bob", "S//NF", "New tasking in your inbox.");
  feeds.ops!.push(m);
  emit("messages_appended", { room: "ops", items: [m] });
}, 4000);
setTimeout(() => emit("denial", { room: "watch", by: "received from mallory", code: null, reason: "above ceiling", audit: null }), 6000);
