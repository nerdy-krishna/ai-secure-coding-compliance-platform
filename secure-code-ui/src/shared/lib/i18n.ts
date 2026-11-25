// secure-code-ui/src/shared/lib/i18n.ts
//
// Translation scaffolding, deliberately minimal.
//
// The expensive part of i18n is not the lookup function, it is extracting every string and keeping
// the translations current. So this provides the mechanism — a locale store, a `t()` that falls
// back to the English key, and a place to add a dictionary — without pretending the app is
// translated. New surfaces use it; existing strings are extracted as they are touched.
//
// Usage:
//   const t = useT();
//   t("coverage.title")            // → "Coverage" (English default)
//   t("coverage.gaps", { n: 3 })   // → interpolated

import { useSyncExternalStore } from "react";

export type Locale = "en" | "ko" | "es" | "ja" | "zh";

export const LOCALES: Array<{ id: Locale; label: string }> = [
  { id: "en", label: "English" },
  { id: "ko", label: "한국어" },
  { id: "es", label: "Español" },
  { id: "ja", label: "日本語" },
  { id: "zh", label: "中文" },
];

const STORAGE_KEY = "sccap.locale";
const listeners = new Set<() => void>();
let current: Locale = read();

function read(): Locale {
  try {
    const stored = localStorage.getItem(STORAGE_KEY) as Locale | null;
    if (stored && LOCALES.some((locale) => locale.id === stored)) return stored;
  } catch {
    /* storage unavailable: the default locale is fine */
  }
  return "en";
}

export function getLocale(): Locale {
  return current;
}

export function setLocale(locale: Locale): void {
  current = LOCALES.some((entry) => entry.id === locale) ? locale : "en";
  try {
    localStorage.setItem(STORAGE_KEY, current);
  } catch {
    /* ignore */
  }
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** English source strings; add a language by adding a dictionary under the key. */
const DICTIONARIES: Partial<Record<Locale, Record<string, string>>> = {
  en: {},
};

export function translate(
  key: string,
  vars?: Record<string, string | number>,
  locale: Locale = current,
): string {
  const dictionary = DICTIONARIES[locale] ?? {};
  const template = dictionary[key] ?? key;
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_match, name: string) =>
    String(vars[name] ?? `{${name}}`),
  );
}

export function useLocale(): Locale {
  return useSyncExternalStore(subscribe, getLocale, () => "en" as Locale);
}

export function useT() {
  const locale = useLocale();
  return (key: string, vars?: Record<string, string | number>) => translate(key, vars, locale);
}
