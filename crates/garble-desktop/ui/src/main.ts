import "./style.css";
import {
  api,
  asUiError,
  on,
  type CredentialState,
  type MessageView,
  type MsgId,
  type RoomSummary,
  type UiError,
} from "./api";
import { chip, showBanner, showBannerFailure, showNoContent } from "./chip";
import { createComposer } from "./composer";
import { clear, h, when } from "./dom";
import {
  count as denialCount,
  errText,
  fromError,
  initInspector,
  inspect,
  openLatest,
  record,
} from "./inspector";
import { startWatermark } from "./watermark";

const $ = (id: string) => document.getElementById(id) as HTMLElement;
const PAGE = 200;

let rooms: RoomSummary[] = [];
let current: { room: RoomSummary; items: MessageView[]; older: number | null } | null = null;
let credential: CredentialState | null = null;
let connection: { ok: boolean; message: string | null } | null = null;
let note = "";
const alerts = new Map<string, string>();

const composer = createComposer({ onSend: sendMessage });

// ─────────────────────────── status, alerts, errors ───────────────────────────

let noteTimer: number | undefined;
function say(text: string) {
  note = text;
  renderStatus();
  window.clearTimeout(noteTimer);
  noteTimer = window.setTimeout(() => {
    note = "";
    renderStatus();
  }, 8000);
}

function renderStatus() {
  const cred = !credential
    ? ""
    : credential.state === "active"
      ? `credential valid until ${when(credential.until)}`
      : credential.state === "expired"
        ? `CREDENTIAL EXPIRED since ${when(credential.since)}`
        : "not enrolled";
  const credBad = credential?.state !== "active";
  const n = denialCount();
  clear(
    $("status"),
    h("span", { class: connection?.ok === false ? "bad" : "ok", text: connection?.ok === false ? `DS unreachable: ${connection.message ?? ""}` : connection ? "connected" : "connecting…" }),
    h("span", { class: credBad && credential ? "bad" : "", text: cred }),
    n > 0 &&
      h("button", {
        class: "plain",
        text: `denials (${n})`,
        on: { click: openLatest },
      }),
    h("span", { class: "note", text: note }),
  );
}

function renderAlerts() {
  const el = $("integrity");
  el.hidden = alerts.size === 0;
  clear(
    el,
    ...[...alerts].map(([k, reason]) =>
      h("div", {
        text:
          k === ""
            ? `LOG INTEGRITY ALERT: sending is stopped, reading carries on. ${reason}`
            : `ROOM FROZEN (${k}): ${reason}`,
      }),
    ),
  );
}

/** Every refusal opens the inspector; everything else is a line in the status bar. */
function fail(room: string, e: unknown) {
  const err: UiError = asUiError(e);
  if (err.kind === "denied") {
    inspect(fromError(room, err));
    renderStatus();
    // The refusal changed what the room says about us; pick it up.
    void refreshRooms();
  } else {
    if (err.kind === "integrity") {
      alerts.set("", err.reason);
      renderAlerts();
    }
    say(errText(err));
  }
}

// ─────────────────────────────── room list ───────────────────────────────

async function refreshRooms() {
  try {
    rooms = (await api.listRooms()).sort((a, b) => a.room.localeCompare(b.room));
  } catch (e) {
    return fail("", e);
  }
  if (current) {
    const fresh = rooms.find((r) => r.room === current?.room.room);
    if (fresh) {
      current.room = fresh;
      renderHead();
      composer.setRoom(fresh);
    }
  }
  renderRooms();
}

const roomList = h("ul");
const newName = h("input", { type: "text", placeholder: "new room", spellcheck: false });
const newCeiling = h("input", { type: "text", placeholder: "ceiling, e.g. TS//SI//NF", spellcheck: false });
// Built once: the list re-renders on every sync, and mustn't eat what you're typing.
$("rooms").append(
  h("h1", { text: "GARBLE" }),
  roomList,
  h(
    "form",
    {
      class: "new-room",
      on: {
        submit: (e) => {
          e.preventDefault();
          void createRoom(newName.value.trim(), newCeiling.value.trim());
        },
      },
    },
    newName,
    newCeiling,
    h("button", { type: "submit", text: "Create" }),
  ),
);

function renderRooms() {
  clear(
    roomList,
    ...rooms.map((r) =>
      h(
        "li",
        {},
        h(
          "button",
          {
            class: `room${r.room === current?.room.room ? " on" : ""}`,
            on: { click: () => void select(r.room) },
          },
          h("span", { class: "room-name", text: r.room }),
          chip(r.ceiling),
          r.held && h("span", { class: "tag bad", text: "FROZEN" }),
          r.unread > 0 && h("span", { class: "badge", text: String(r.unread) }),
        ),
      ),
    ),
  );
}

async function createRoom(room: string, ceiling: string) {
  if (!room || !ceiling) return say("a room needs a name and a ceiling");
  try {
    await api.createRoom(room, ceiling);
  } catch (e) {
    return fail(room, e);
  }
  newName.value = "";
  newCeiling.value = "";
  await refreshRooms();
  await select(room);
}

// ─────────────────────────────── room view ───────────────────────────────

const head = h("header", { class: "room-head" });
const list = h("div", { class: "messages" });
const empty = h("div", { class: "empty", text: "Pick a room." });
$("room").append(head, list, empty, composer.el);
composer.setRoom(null);
initInspector($("inspector"));

const seen = new Map<string, MsgId>();
let bannerTimer: number | undefined;
const observer = new IntersectionObserver(
  (entries) => {
    for (const e of entries) {
      const el = e.target as HTMLElement;
      const key = el.dataset.key ?? "";
      if (e.isIntersecting) {
        seen.set(key, { room: el.dataset.room ?? "", seq: Number(el.dataset.seq) });
      } else {
        seen.delete(key);
      }
    }
    window.clearTimeout(bannerTimer);
    bannerTimer = window.setTimeout(() => void refreshBanner(), 30);
  },
  { root: list, threshold: 0.5 },
);

async function refreshBanner() {
  if (seen.size === 0) return showNoContent();
  try {
    showBanner(await api.banner([...seen.values()]));
  } catch {
    showBannerFailure();
  }
}

async function select(room: string) {
  try {
    const page = await api.openRoom(room, null, PAGE);
    const summary = rooms.find((r) => r.room === room);
    if (!summary) return;
    current = { room: summary, items: page.items, older: page.older };
  } catch (e) {
    return fail(room, e);
  }
  renderHead();
  composer.setRoom(current.room);
  renderMessages("bottom");
  await refreshRooms();
}

const titleEl = h("div", { class: "title" });
const membersEl = h("div", { class: "members" });
const memberName = h("input", { type: "text", placeholder: "user", spellcheck: false });
const memberAct = (add: boolean) => async () => {
  const room = current?.room.room;
  const user = memberName.value.trim();
  if (!room || !user) return;
  try {
    await (add ? api.addMember : api.removeMember)(room, user);
    memberName.value = "";
    say(`${add ? "added" : "removed"} ${user}`);
  } catch (e) {
    fail(room, e);
  }
};
const controls = h(
  "div",
  { class: "member-controls" },
  memberName,
  h("button", { text: "Add", on: { click: memberAct(true) } }),
  h("button", { text: "Remove", on: { click: memberAct(false) } }),
);
head.append(titleEl, membersEl, controls);
head.hidden = true;

function renderHead() {
  head.hidden = !current;
  if (!current) return;
  const r = current.room;
  clear(
    titleEl,
    h("strong", { text: r.room }),
    chip(r.ceiling),
    r.held && h("span", { class: "tag bad", text: "FROZEN" }),
  );
  membersEl.textContent = `members: ${r.members.map((m) => (r.stewards.includes(m) ? `${m} (steward)` : m)).join(", ")}`;
}

function renderMessages(stick: "bottom" | "keep") {
  const view = current;
  empty.hidden = !!view;
  list.hidden = !view;
  if (!view) return showNoContent();
  const nearEnd = list.scrollHeight - list.scrollTop - list.clientHeight < 40;
  const was = list.scrollTop;
  observer.disconnect();
  seen.clear();
  clear(
    list,
    view.older !== null &&
      h("button", { class: "plain older", text: "load older", on: { click: () => void loadOlder() } }),
    ...view.items.map(messageEl),
  );
  list.scrollTop = stick === "bottom" || nearEnd ? list.scrollHeight : was;
  list.querySelectorAll<HTMLElement>("[data-key]").forEach((el) => observer.observe(el));
  if (!list.querySelector("[data-key]")) void refreshBanner();
}

async function loadOlder() {
  const view = current;
  if (!view || view.older === null) return;
  try {
    const page = await api.openRoom(view.room.room, view.older, PAGE);
    if (current !== view) return;
    view.items = [...page.items, ...view.items];
    view.older = page.older;
    renderMessages("keep");
  } catch (e) {
    fail(view.room.room, e);
  }
}

function messageEl(m: MessageView): HTMLElement {
  const where = { room: m.id.room, seq: String(m.id.seq) };
  switch (m.kind) {
    case "notice":
      return h("div", { class: "msg notice", text: `#${m.id.seq} ${m.sender}: ${m.text}` });
    case "quarantined":
      return h(
        "div",
        { class: "msg quarantined" },
        h(
          "div",
          { class: "meta" },
          h("strong", { text: "QUARANTINED" }),
          ` message from ${m.sender} (#${m.id.seq}). Body not shown.`,
        ),
        h("div", { class: "text", text: m.text }),
        h("button", {
          class: "plain",
          text: "inspect",
          on: {
            click: () =>
              inspect({ room: m.id.room, by: `received from ${m.sender}`, code: null, reason: m.text, audit: null }),
          },
        }),
      );
    case "ack":
      return h(
        "div",
        { class: "msg ack", data: { ...where, key: `${m.id.room}:${m.id.seq}` } },
        m.marking && chip(m.marking),
        h("span", { text: ` ROGER from ${m.sender}` }),
        h("span", { class: "muted", text: m.of === null ? " for a message this client doesn't have" : ` for #${m.of}` }),
      );
    case "message":
      return h(
        "div",
        { class: `msg${m.mine ? " mine" : ""}`, data: { ...where, key: `${m.id.room}:${m.id.seq}` } },
        h(
          "div",
          { class: "meta" },
          m.marking && chip(m.marking),
          h("span", { class: "sender", text: m.sender }),
          h("span", { class: "muted", text: `#${m.id.seq}` }),
          m.forwarded_from && h("span", { class: "tag", text: `forwarded from ${m.forwarded_from}` }),
        ),
        h("div", { class: "text", text: m.text }),
      );
  }
}

async function sendMessage(marking: string, body: string): Promise<boolean> {
  if (!current) return false;
  try {
    await api.send(current.room.room, marking, body);
    return true;
  } catch (e) {
    fail(current.room.room, e);
    return false;
  }
}

function appended(room: string, items: MessageView[]) {
  if (current?.room.room !== room) return void refreshRooms();
  const have = new Set(current.items.map((m) => m.id.seq));
  const fresh = items.filter((m) => !have.has(m.id.seq));
  if (fresh.length === 0) return;
  current.items = [...current.items, ...fresh].sort((a, b) => a.id.seq - b.id.seq);
  renderMessages("keep");
}

// ─────────────────────────────── core events ───────────────────────────────

async function main() {
  // `npm run dev` in a plain browser has no core behind it; fake one.
  if (import.meta.env.DEV && !("__TAURI_INTERNALS__" in window)) await import("./mock");
  // Listen before the first read, so nothing lands in the gap. Items are de-duplicated by seq.
  await Promise.all([
    on("messages_appended", (p) => appended(p.room, p.items)),
    on("room_changed", (p) => {
      if (p.change === "purged" && current?.room.room === p.room) {
        current = null;
        renderMessages("keep");
        composer.setRoom(null);
        renderHead();
        say(`you were removed from ${p.room}; the local copy is purged`);
      }
      void refreshRooms();
    }),
    on("denial", (d) => {
      record(d);
      renderStatus();
      say(`refused: ${d.reason}`);
    }),
    on("credential_state", (s) => {
      const changed = JSON.stringify(s) !== JSON.stringify(credential);
      credential = s;
      if (changed) renderStatus();
    }),
    on("integrity_alert", (p) => {
      const key = p.room ?? "";
      const had = alerts.has(key);
      alerts.set(key, p.reason);
      if (!had) renderAlerts();
    }),
    on("connection", (c) => {
      const changed = c.ok !== connection?.ok || c.message !== connection?.message;
      connection = c;
      if (changed) renderStatus();
    }),
  ]);
  renderStatus();
  showNoContent();
  startWatermark($("watermark")).catch((e) => say(`watermark: ${errText(asUiError(e))}`));
  await refreshRooms();
}

void main();
