export type Theme = "dark" | "light";

const STORAGE_KEY = "nullapart-theme";

const listeners = new Set<() => void>();

export function readStoredTheme(): Theme {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

export function persistTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* storage unavailable: theme still applies for this session */
  }
}

export function applyStoredTheme(): void {
  document.documentElement.dataset.theme = readStoredTheme();
}

/**
 * Single write path for the theme so the sidebar toggle and the Settings
 * page stay in sync; every subscriber re-reads from localStorage.
 */
export function setTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  persistTheme(theme);
  for (const listener of listeners) listener();
}

export function subscribeTheme(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
