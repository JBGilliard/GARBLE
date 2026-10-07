import { api, asUiError, type Denial, type DenialDetail, type UiError } from "./api";
import { clear, h, when } from "./dom";

const history: Denial[] = [];
let selected: Denial | null = null;
const details = new Map<string, Promise<DenialDetail>>();
let root: HTMLElement;

export function initInspector(el: HTMLElement) {
  root = el;
}

export function fromError(room: string, e: Extract<UiError, { kind: "denied" }>): Denial {
  return { room, by: e.by, code: e.code, reason: e.reason, audit: e.audit };
}

/** Remember a refusal without taking over the screen. */
export function record(d: Denial): number {
  history.unshift(d);
  if (root && !root.hidden) render();
  return history.length;
}

export function inspect(d: Denial) {
  if (!history.includes(d)) history.unshift(d);
  selected = d;
  root.hidden = false;
  render();
}

export function count() {
  return history.length;
}

export function openLatest() {
  const d = history[0];
  if (d) inspect(d);
}

const isRef = (a: string | null): a is string => !!a && /^L-\d+$/.test(a);

function fetchDetail(ref: string) {
  let p = details.get(ref);
  if (!p) {
    p = api.denial(ref);
    details.set(ref, p);
    // A failed lookup isn't a fact about the entry; ask again next time.
    p.catch(() => details.delete(ref));
  }
  return p;
}

function row(k: string, v: string | Node) {
  return h("tr", {}, h("th", { text: k }), h("td", {}, v));
}

function summary(d: Denial) {
  const label = [d.code, d.reason].filter(Boolean).join(" ");
  return h("button", {
    class: `denial-row${d === selected ? " on" : ""}`,
    text: `${d.room || "log"}: ${label}`,
    title: label,
    on: {
      click: () => {
        selected = d;
        render();
      },
    },
  });
}

function render() {
  const d = selected ?? history[0] ?? null;
  const proof = h("div", { class: "proof" });
  clear(
    root,
    h(
      "div",
      { class: "inspector-head" },
      h("strong", { text: `Denials this session (${history.length})` }),
      h("button", {
        class: "plain",
        text: "close",
        on: { click: () => (root.hidden = true) },
      }),
    ),
    h("div", { class: "denial-list" }, ...history.map(summary)),
    d &&
      h(
        "section",
        { class: "denial-detail" },
        h(
          "table",
          {},
          row("code", d.code ?? "none: this client's own check gave no code"),
          row("reason", d.reason),
          row("refused by", d.by),
          row("room", d.room || "(log)"),
          row("audit ref", d.audit ?? "not logged"),
        ),
        proof,
      ),
  );
  if (d) void fillProof(d, proof);
}

async function fillProof(d: Denial, el: HTMLElement) {
  if (!isRef(d.audit)) {
    clear(
      el,
      h("p", {
        class: "muted",
        text:
          d.audit && d.audit !== "not logged"
            ? `Not logged: ${d.audit}`
            : "Nothing logged this refusal, so there is no record to prove.",
      }),
    );
    return;
  }
  clear(el, h("p", { class: "muted", text: "Checking the log…" }));
  let detail: DenialDetail;
  try {
    detail = await fetchDetail(d.audit);
  } catch (e) {
    if (el.isConnected) clear(el, h("p", { class: "bad", text: errText(asUiError(e)) }));
    return;
  }
  if (!el.isConnected) return; // another denial was selected meanwhile
  const inc = detail.inclusion;
  const log = detail.entry;
  clear(
    el,
    h(
      "p",
      { class: inc.status === "proven" ? "ok" : "warn" },
      inc.status === "proven"
        ? `Inclusion proven: entry is in the log tree of size ${inc.size} (root ${inc.root.slice(0, 16)}…)`
        : "Withheld: this log entry is above your clearance. It exists; you can't read it.",
    ),
    log &&
      h(
        "table",
        {},
        row("entry", `L-${log.id}`),
        row("at", when(log.at)),
        row("actor", log.actor),
        row("event", `${log.event} → ${log.decision}${log.code ? ` [${log.code}]` : ""}`),
        row("detail", log.detail),
        row("entry marking", log.marking),
      ),
  );
}

export function errText(e: UiError): string {
  switch (e.kind) {
    case "denied":
      return `Denied by ${e.by} [${e.code}] ${e.reason}`;
    case "integrity":
      return `Integrity alert: ${e.reason}`;
    case "failed":
      return e.message;
  }
}
