type Child = Node | string | null | undefined | false;
type Props = {
  class?: string;
  text?: string;
  title?: string;
  hidden?: boolean;
  disabled?: boolean;
  type?: string;
  value?: string;
  placeholder?: string;
  rows?: number;
  autocomplete?: string;
  spellcheck?: boolean;
  data?: Record<string, string>;
  on?: { [K in keyof HTMLElementEventMap]?: (e: HTMLElementEventMap[K]) => void };
};

/** Just enough element builder. Text always goes in as text, never as HTML. */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Props = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  const { class: cls, text, data, on: handlers, ...rest } = props;
  if (cls) el.className = cls;
  if (text !== undefined) el.textContent = text;
  for (const [k, v] of Object.entries(rest)) {
    if (v !== undefined) (el as unknown as Record<string, unknown>)[k] = v;
  }
  for (const [k, v] of Object.entries(data ?? {})) el.dataset[k] = v;
  for (const [k, f] of Object.entries(handlers ?? {})) {
    el.addEventListener(k, f as EventListener);
  }
  for (const c of children) if (c) el.append(c);
  return el;
}

export function clear(el: Element, ...children: Child[]) {
  el.replaceChildren(...children.filter((c): c is Node | string => !!c));
}

export function when(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}
