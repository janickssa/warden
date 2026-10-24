"use client";
// English or Dansk (README 17.2). The English text is the key; da.ts holds the Danish. Commands, IDs and
// policy paths are never translated. scripts/check-i18n.mjs fails if a t("…") string has no Danish entry.
import { createContext, useContext, useMemo } from "react";
import { da } from "./da";
import { interp } from "./format";

export type Lang = "en" | "da";
export type T = (s: string, v?: Record<string, string | number>) => string;

const Ctx = createContext<{ lang: Lang; t: T }>({ lang: "en", t: (s, v) => interp(s, v) });

export function I18nProvider({ lang, children }: { lang: Lang; children: React.ReactNode }) {
  const value = useMemo(() => {
    const t: T = (s, v) => interp(lang === "da" ? (da[s] ?? s) : s, v);
    return { lang, t };
  }, [lang]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useT = () => useContext(Ctx).t;
export const useLang = () => useContext(Ctx).lang;

/** Marks a string in a table as translatable (it is passed through t() where it's shown). */
export const N = (s: string) => s;
