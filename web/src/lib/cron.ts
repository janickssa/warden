// Cron in plain language for the dashboard (README 17.3 Schedules: "Every day at 03:00"). Warden and the
// agents evaluate cron; this only describes the common shapes and otherwise shows the expression.
import { N, type T } from "./i18n";

const DAYS = [N("Sunday"), N("Monday"), N("Tuesday"), N("Wednesday"), N("Thursday"), N("Friday"), N("Saturday")];

export function describeCron(expr: string, t: T): string {
  const f = expr.split(" ");
  if (f.length !== 5) return expr;
  const [m, h, dom, mon, dow] = f as [string, string, string, string, string];
  const num = (s: string) => /^\d{1,2}$/.test(s);
  if (expr === "* * * * *") return t("Every minute");
  const hourly = m.match(/^\*\/(\d+)$/);
  if (hourly && h === "*" && dom === "*" && mon === "*" && dow === "*") return t("Every {n} minutes", { n: hourly[1]! });
  if (!num(m) || !num(h) || mon !== "*") return expr;
  const at = `${h.padStart(2, "0")}:${m.padStart(2, "0")}`;
  if (dom === "*" && dow === "*") return t("Every day at {time}", { time: at });
  if (dom === "*" && dow === "1-5") return t("Every weekday at {time}", { time: at });
  if (dom === "*" && /^[0-7]$/.test(dow)) return t("Every {day} at {time}", { day: t(DAYS[Number(dow) % 7]!), time: at });
  if (dow === "*" && num(dom)) return t("On day {n} of every month at {time}", { n: dom, time: at });
  return expr;
}

export const CRON_PRESETS: { cron: string; label: string }[] = [
  { cron: "0 3 * * *", label: N("Every day at 03:00") },
  { cron: "0 3 * * 1-5", label: N("Every weekday at 03:00") },
  { cron: "0 6 * * 1", label: N("Every Monday at 06:00") },
  { cron: "0 4 1 * *", label: N("On day 1 of every month at 04:00") },
];
