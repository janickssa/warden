// README 17.2 formats: 20.10.2026, 14:32 (24-hour, Europe/Copenhagen), 1 min 12 s, MB/GB.
const TZ = "Europe/Copenhagen";
const timeFmt = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", minute: "2-digit", hour12: false });
const timeSecFmt = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const dateFmt = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, day: "2-digit", month: "2-digit", year: "numeric" });

const d = (ts: string | number | Date) => (ts instanceof Date ? ts : new Date(ts));
export const fmtTime = (ts: string | number | Date, seconds = false) => (seconds ? timeSecFmt : timeFmt).format(d(ts));
export const fmtDate = (ts: string | number | Date) => dateFmt.format(d(ts)).replaceAll("/", ".");
export const fmtExact = (ts: string | number | Date) => `${fmtDate(ts)} ${fmtTime(ts)}`;

export function fmtRel(ts: string | number | Date, now = Date.now(), t: (s: string, v?: Record<string, string | number>) => string = (s, v) => interp(s, v)): string {
  const min = Math.floor((now - d(ts).getTime()) / 60000);
  if (min < 1) return t("just now");
  if (min < 60) return t("{n} min ago", { n: min });
  if (min < 24 * 60) return t("{n} h ago", { n: Math.floor(min / 60) });
  return fmtDate(ts);
}

export function fmtDur(sec: number | null | undefined): string {
  if (sec == null) return "";
  const s = Math.round(sec);
  return s < 60 ? `${s} s` : `${Math.floor(s / 60)} min ${s % 60} s`;
}

export function fmtCountdown(ms: number): string {
  if (ms <= 0) return "00:00";
  const total = Math.floor(ms / 1000);
  return `${String(Math.floor(total / 60)).padStart(2, "0")}:${String(total % 60).padStart(2, "0")}`;
}

export function fmtBytes(n: number): string {
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${Math.round(n / 1024 ** 2)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} kB`;
  return `${n} B`;
}

export function interp(s: string, v?: Record<string, string | number>): string {
  return v ? s.replace(/\{(\w+)\}/g, (_, k) => String(v[k] ?? `{${k}}`)) : s;
}
