import { Moon, Sun } from "lucide-react";
import { useSyncExternalStore } from "react";
import { readStoredTheme, setTheme, subscribeTheme, type Theme } from "../lib/theme";

/**
 * Header control that flips the console between the light (default) and dark
 * themes. The choice persists per browser profile; it is a display preference
 * only and never affects server-side access.
 */
export function ThemeToggle() {
  const theme = useSyncExternalStore(subscribeTheme, readStoredTheme, readStoredTheme);

  const next: Theme = theme === "dark" ? "light" : "dark";
  const label = next === "light" ? "Switch to light theme" : "Switch to dark theme";

  return (
    <button
      type="button"
      className="theme-toggle"
      aria-label={label}
      aria-pressed={theme === "light"}
      title={label}
      onClick={() => setTheme(next)}
    >
      {theme === "dark" ? (
        <Sun size={16} aria-hidden="true" />
      ) : (
        <Moon size={16} aria-hidden="true" />
      )}
    </button>
  );
}
