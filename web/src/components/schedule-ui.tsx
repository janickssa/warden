"use client";
// Shared bits for the schedule pages: state badges, next-run text.
import { fmtDate, fmtExact, fmtTime } from "@/lib/format";
import { N, useT } from "@/lib/i18n";

const STATES: Record<string, [string, string]> = {
  awaiting_approval: [N("⏸ Awaiting approval"), "warn"],
  active: [N("Active"), "tag"],
  paused: [N("Paused"), "tag-neutral"],
  stopped: [N("■ Stopped"), "danger"],
  expired: [N("— Expired"), "neutral"],
  invalidated: [N("⊘ Invalidated"), "warn"],
};

export function ScheduleState({ status }: { status: string }) {
  const t = useT();
  const [label, c] = STATES[status] ?? [status, "neutral"];
  if (c === "tag") return <span className="tag tag-accent" data-state={status}>{t(label)}</span>;
  if (c === "tag-neutral") return <span className="tag tag-neutral" data-state={status}>{t(label)}</span>;
  return (
    <span className={`w-badge c-${c}`} data-state={status}>
      {t(label)}
    </span>
  );
}

/** "Today 03:00", "Tomorrow 03:00", else "26.10.2026 06:00" (Europe/Copenhagen). */
export function useNextRun(): (ts: string | null | undefined) => string {
  const t = useT();
  return (ts) => {
    if (!ts) return "—";
    const day = fmtDate(ts);
    const today = fmtDate(new Date());
    const tomorrow = fmtDate(new Date(Date.now() + 86_400_000));
    if (day === today) return t("Today {time}", { time: fmtTime(ts) });
    if (day === tomorrow) return t("Tomorrow {time}", { time: fmtTime(ts) });
    return fmtExact(ts);
  };
}
