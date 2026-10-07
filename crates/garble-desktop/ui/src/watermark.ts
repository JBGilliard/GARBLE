import { api } from "./api";

// Deters and attributes; a compromised endpoint defeats it (architecture §7.5).
export async function startWatermark(el: HTMLElement) {
  const { text, seed } = await api.watermark();
  // The seed only nudges the tiling, so two screenshots from one user still differ.
  const n = parseInt(seed.slice(0, 8), 16);
  const dx = n % 40;
  const dy = (n >>> 8) % 30;
  const esc = (s: string) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="360" height="200">` +
    `<text x="${20 + dx}" y="${120 + dy}" transform="rotate(-24 180 100)" ` +
    `font-family="monospace" font-size="15" fill="rgba(255,255,255,0.09)">${esc(text)}</text></svg>`;
  el.style.backgroundImage = `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
}
