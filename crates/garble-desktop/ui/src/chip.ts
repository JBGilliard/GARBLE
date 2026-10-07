import { clear, h } from "./dom";
import type { MarkingView } from "./api";

export function chip(m: MarkingView, extra = ""): HTMLElement {
  const el = h("span", { class: `chip ${extra}`.trim(), text: m.portion, title: m.banner });
  el.style.setProperty("--bg", m.colors.bg);
  el.style.setProperty("--fg", m.colors.fg);
  return el;
}

const top = () => document.getElementById("top-banner") as HTMLElement;
const bottom = () => document.getElementById("bottom-banner") as HTMLElement;

function paint(text: string, bg: string, fg: string, cls: string) {
  for (const el of [top(), bottom()]) {
    clear(el, h("span", { text }));
    el.className = `banner ${cls}`;
    el.style.setProperty("--bg", bg);
    el.style.setProperty("--fg", fg);
  }
}

/** High-water mark of what's on screen, as the core computed it. */
export function showBanner(m: MarkingView) {
  paint(m.banner, m.colors.bg, m.colors.fg, "");
}

/** Nothing marked is on screen. Deliberately not green: it isn't UNCLASSIFIED. */
export function showNoContent() {
  paint("NO MARKED CONTENT DISPLAYED", "#3a3f4b", "#c9ced8", "idle");
}

/** The core couldn't say. Loud, and never a lower classification than the truth. */
export function showBannerFailure() {
  paint("BANNER UNAVAILABLE: TREAT AS HIGHEST CLASSIFICATION", "#7a1f9c", "#ffffff", "fault");
}
