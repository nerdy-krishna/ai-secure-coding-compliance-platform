// secure-code-ui/src/app/providers/ThemeProvider.tsx
//
// Manages the SCCAP theme mode + color-variation attributes on
// document.documentElement.  Preferences are stored server-side
// (GET/PUT /api/v1/account/preferences) and mirrored to localStorage
// as a fast local cache so the theme applies instantly on page load
// before the API call resolves.

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { preferencesService } from "../../shared/api/preferencesService";

export type SccapTheme = "light" | "dark";
export type SccapVariant = "A" | "B";

interface ThemeContextValue {
  theme: SccapTheme;
  variant: SccapVariant;
  accent: string;
  setTheme: (theme: SccapTheme) => void;
  setVariant: (variant: SccapVariant) => void;
  setAccent: (accent: string) => void;
  toggleTheme: () => void;
}

const STORAGE_KEYS = {
  theme: "sccap-theme",
  variant: "sccap-variant",
  accent: "sccap-accent",
  role: "sccap-role",
} as const;

const ThemeContext = createContext<ThemeContextValue | null>(null);

function readStored<T extends string>(
  key: string,
  fallback: T,
  valid: readonly T[],
): T {
  if (typeof window === "undefined") return fallback;
  const raw = window.localStorage.getItem(key);
  return valid.includes(raw as T) ? (raw as T) : fallback;
}

// Allow-list regex for CSS color values accepted as accent overrides.
const ACCENT_RE =
  /^#[0-9a-fA-F]{3,8}$|^(rgb|rgba|hsl|hsla|oklch|color)\([^;{}]{0,80}\)$/i;

function safeAccent(raw: string): string {
  const trimmed = raw.slice(0, 128);
  return ACCENT_RE.test(trimmed) && !/[;{}]/.test(trimmed) ? trimmed : "";
}

function readAccent(): string {
  if (typeof window === "undefined") return "";
  const raw = window.localStorage.getItem(STORAGE_KEYS.accent) || "";
  return safeAccent(raw);
}

/** Debounced server-sync helper — avoids PUT-ing on every keystroke or
 *  rapid toggle.  500ms is short enough that theme changes feel
 *  instantaneous but long enough to coalesce variant + accent changes.
 *  Only syncs when there's an access token. */
let _syncTimer: ReturnType<typeof setTimeout> | null = null;
function _scheduleSync(prefs: {
  theme: SccapTheme;
  variant: SccapVariant;
  accent: string;
}) {
  if (typeof window === "undefined") return;
  if (!window.localStorage.getItem("accessToken")) return;
  if (_syncTimer) clearTimeout(_syncTimer);
  _syncTimer = setTimeout(() => {
    preferencesService
      .update({
        theme: prefs.theme,
        variant: prefs.variant,
        accent: prefs.accent || null,
      })
      .catch(() => {
        // Best-effort — localStorage already has it.
      });
  }, 500);
}

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [theme, setThemeState] = useState<SccapTheme>(() =>
    readStored<SccapTheme>(STORAGE_KEYS.theme, "light", ["light", "dark"]),
  );
  const [variant, setVariantState] = useState<SccapVariant>(() =>
    readStored<SccapVariant>(STORAGE_KEYS.variant, "A", ["A", "B"]),
  );
  const [accent, setAccentState] = useState<string>(() => readAccent());
  // Track whether we've pulled from the server yet so we don't
  // overwrite a user's deliberate choice with a stale server value
  // on a re-render.
  const [serverSynced, setServerSynced] = useState(false);

  // Drop the legacy role entry.
  useEffect(() => {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(STORAGE_KEYS.role);
    }
  }, []);

  // On mount: pull preferences from the server.  Only run when the
  // user has an access token — the login page has no token and the
  // 401 interceptor would redirect to /login, causing a reload loop.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const token = window.localStorage.getItem("accessToken");
    if (!token) {
      setServerSynced(true);
      return;
    }
    let cancelled = false;
    preferencesService
      .get()
      .then((prefs) => {
        if (cancelled) return;
        const hasServerPrefs =
          prefs.theme || prefs.variant || prefs.accent;
        if (hasServerPrefs) {
          // Server has stored preferences — apply them, overriding
          // localStorage defaults.
          if (
            prefs.theme &&
            (prefs.theme === "light" || prefs.theme === "dark")
          ) {
            setThemeState(prefs.theme);
            window.localStorage.setItem(STORAGE_KEYS.theme, prefs.theme);
          }
          if (prefs.variant && (prefs.variant === "A" || prefs.variant === "B")) {
            setVariantState(prefs.variant);
            window.localStorage.setItem(STORAGE_KEYS.variant, prefs.variant);
          }
          if (prefs.accent) {
            const acc = safeAccent(prefs.accent);
            if (acc) {
              setAccentState(acc);
              window.localStorage.setItem(STORAGE_KEYS.accent, acc);
            }
          }
        } else {
          // No server prefs yet — push our current localStorage
          // values up so they persist across browsers going forward.
          preferencesService
            .update({
              theme,
              variant,
              accent: accent || null,
            })
            .catch(() => {});
        }
        setServerSynced(true);
      })
      .catch(() => {
        // Network error — keep localStorage values.
        setServerSynced(true);
      });
    return () => {
      cancelled = true;
    };
    // Run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Write attributes + persist to localStorage on every change.
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    document.documentElement.setAttribute("data-variant", variant);
    window.localStorage.setItem(STORAGE_KEYS.theme, theme);
    window.localStorage.setItem(STORAGE_KEYS.variant, variant);
    // Sync to server (debounced) once initial fetch settles.
    if (serverSynced) {
      _scheduleSync({ theme, variant, accent });
    }
  }, [theme, variant, accent, serverSynced]);

  // Accent override.
  useEffect(() => {
    const validated = safeAccent(accent);
    window.localStorage.setItem(STORAGE_KEYS.accent, validated);
    if (validated) {
      document.documentElement.style.setProperty("--primary", validated);
      document.documentElement.style.setProperty("--primary-strong", validated);
    } else {
      document.documentElement.style.removeProperty("--primary");
      document.documentElement.style.removeProperty("--primary-strong");
    }
  }, [accent]);

  const toggleTheme = useCallback(() => {
    setThemeState((t) => (t === "light" ? "dark" : "light"));
  }, []);

  const value = useMemo<ThemeContextValue>(
    () => ({
      theme,
      variant,
      accent,
      setTheme: setThemeState,
      setVariant: setVariantState,
      setAccent: setAccentState,
      toggleTheme,
    }),
    [theme, variant, accent, toggleTheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
};

export function useTheme(): ThemeContextValue {
  const ctx = useContext(ThemeContext);
  if (!ctx) {
    throw new Error("useTheme must be used inside a ThemeProvider.");
  }
  return ctx;
}
