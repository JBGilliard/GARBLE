import { api, asUiError, type MarkingCheck, type RoomSummary } from "./api";
import { chip } from "./chip";
import { clear, h } from "./dom";
import { errText } from "./inspector";

type Opts = { onSend: (marking: string, body: string) => Promise<boolean> };

/**
 * The marking field is checked by the core as you type: same parse and same policy
 * check a send would face, but nothing is reported to the DS until you actually send.
 */
export function createComposer({ onSend }: Opts) {
  let room: RoomSummary | null = null;
  let check: MarkingCheck | null = null;
  let failure: string | null = null;
  let ticket = 0;
  let busy = false;
  let timer: number | undefined;

  const marking = h("input", {
    class: "marking-input",
    type: "text",
    spellcheck: false,
    autocomplete: "off",
    placeholder: "marking, e.g. S//NF",
    on: { input: () => schedule() },
  });
  const verdict = h("div", { class: "verdict" });
  verdict.setAttribute("aria-live", "polite");
  const body = h("textarea", {
    class: "body-input",
    rows: 2,
    placeholder: "message",
    on: {
      input: () => paint(),
      keydown: (e) => {
        if (e.key === "Enter" && !e.shiftKey && !e.isComposing) {
          e.preventDefault();
          void send();
        }
      },
    },
  });
  const button = h("button", { class: "send", type: "submit", text: "Send" });
  const el = h(
    "form",
    {
      class: "composer",
      on: {
        submit: (e) => {
          e.preventDefault();
          void send();
        },
      },
    },
    h("div", { class: "marking-row" }, marking, verdict),
    h("div", { class: "body-row" }, body, button),
  );

  function schedule() {
    paint();
    window.clearTimeout(timer);
    timer = window.setTimeout(() => void validate(), 120);
  }

  async function validate() {
    const mine = ++ticket;
    const text = marking.value.trim();
    if (!room || !text) {
      check = null;
      failure = null;
      return paint();
    }
    try {
      const r = await api.validateMarking(room.room, text);
      if (mine !== ticket) return; // a newer keystroke is already in flight
      check = r;
      failure = null;
    } catch (e) {
      if (mine !== ticket) return;
      check = null;
      failure = errText(asUiError(e));
    }
    paint();
  }

  function canSend() {
    return (
      !!room &&
      !room.held &&
      !busy &&
      body.value.trim() !== "" &&
      check !== null &&
      check.decision.result !== "invalid"
    );
  }

  function paint() {
    const d = check?.decision;
    verdict.className = `verdict ${d?.result ?? (failure ? "deny" : "")}`;
    clear(
      verdict,
      check?.parsed && chip(check.parsed),
      h("span", {
        text: room?.held
          ? "room frozen after a fork: nothing can be sent"
          : failure
            ? failure
            : !d
              ? marking.value.trim()
                ? "checking…"
                : "every message needs a marking"
              : d.result === "permit"
                ? "permitted in this room"
                : d.result === "deny"
                  ? `would be refused [${d.code}] ${d.reason}`
                  : `not a valid marking [${d.code}] ${d.reason}`,
      }),
    );
    button.disabled = !canSend();
    button.textContent = d?.result === "deny" ? "Send (will be refused)" : "Send";
  }

  async function send() {
    if (!canSend()) return;
    busy = true;
    paint();
    let sent = false;
    try {
      sent = await onSend(marking.value.trim(), body.value);
    } finally {
      busy = false;
    }
    if (sent) body.value = "";
    paint();
    body.focus();
  }

  return {
    el,
    setRoom(r: RoomSummary | null) {
      const changed = r?.room !== room?.room;
      room = r;
      el.hidden = !r;
      body.disabled = !r || r.held;
      marking.disabled = !r || r.held;
      if (changed) {
        marking.value = r?.ceiling.portion ?? "";
        body.value = "";
        check = null;
      }
      schedule();
    },
  };
}
