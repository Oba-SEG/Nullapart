/**
 * Nullapart transient notification bus.
 *
 * A tiny in-memory pub/sub for success/error confirmations. Notifications are
 * ephemeral UI affordances only: they never carry secrets or message content,
 * and every mutation remains audited server-side regardless of display.
 */

export type NotifyTone = "success" | "error";

export interface NotifyMessage {
  id: number;
  message: string;
  tone: NotifyTone;
}

type Listener = (messages: NotifyMessage[]) => void;

const listeners = new Set<Listener>();
let messages: NotifyMessage[] = [];
let nextId = 1;
const TTL_MS = 5_000;

function emit(): void {
  for (const listener of listeners) listener([...messages]);
}

export function notify(message: string, tone: NotifyTone = "success"): void {
  const entry: NotifyMessage = { id: nextId++, message, tone };
  messages = [...messages, entry].slice(-4);
  emit();
  window.setTimeout(() => {
    messages = messages.filter((item) => item.id !== entry.id);
    emit();
  }, TTL_MS);
}

export function dismissNotify(id: number): void {
  messages = messages.filter((item) => item.id !== id);
  emit();
}

export function subscribeNotify(listener: Listener): () => void {
  listeners.add(listener);
  listener([...messages]);
  return () => {
    listeners.delete(listener);
  };
}
