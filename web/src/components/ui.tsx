"use client";
// Small shared pieces: status badges (spec 0.3), relative times with the exact time on hover, countdowns,
// skeletons and empty states (README 17.6).
import { CircleNotch } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { fmtCountdown, fmtExact, fmtRel, fmtTime } from "@/lib/format";
import { N, useT } from "@/lib/i18n";

type Colour = "ok" | "warn" | "danger" | "accent" | "neutral";

export const BADGES: Record<string, [string, Colour]> = {
  low: [N("● Low risk"), "ok"],
  medium: [N("▲ Medium risk"), "warn"],
  high: [N("■ High risk"), "danger"],
  allow: [N("✓ Allow"), "ok"],
  escalate: [N("▲ Escalate"), "warn"],
  deny: [N("✕ Deny"), "danger"],
  awaiting_approval: [N("⏸ Awaiting"), "warn"],
  approved: [N("✓ Approved"), "accent"],
  running: [N("◌ Running"), "accent"],
  succeeded: [N("✓ Succeeded"), "ok"],
  failed: [N("✕ Failed"), "danger"],
  refused: [N("✕ Refused"), "danger"],
  rejected: [N("✕ Rejected"), "neutral"],
  cancelled: [N("— Cancelled"), "neutral"],
  expired: [N("— Expired"), "neutral"],
  skipped: [N("— Skipped"), "neutral"],
  pending: [N("· Pending"), "neutral"],
  reviewing: [N("◌ Re-reviewing"), "accent"],
  invalidated: [N("⊘ Invalidated"), "warn"],
  held: [N("⏸ Held"), "warn"],
  tighten: [N("↓ Tighten"), "ok"],
  loosen: [N("↑ Loosen"), "warn"],
  initial: [N("↑ Initial"), "warn"],
  none: [N("No changes"), "neutral"],
  agent_current: [N("● Online"), "ok"],
  agent_behind: [N("⏳ Behind on policy"), "warn"],
  agent_offline: [N("■ Offline"), "danger"],
  agent_revoked: [N("✕ Revoked"), "neutral"],
  agent_not_enrolled: [N("○ Not enrolled"), "neutral"],
  lockdown: [N("■ Lockdown"), "danger"],
  rotate: [N("↻ Key change"), "neutral"],
};

export const colourVar = (c: Colour) =>
  c === "accent" ? "var(--color-accent-300)" : c === "neutral" ? "var(--color-neutral-500)" : `var(--color-${c})`;

export function badgeOf(key: string): [string, Colour] {
  return BADGES[key] ?? [key, "neutral"];
}

/** The status a plan shows: approved-but-held reads as held. */
export const planBadgeKey = (p: { status: string; held_reason?: string | null }) =>
  p.status === "approved" && p.held_reason ? "held" : p.status;

export function Badge({ k, prefix, text }: { k: string; prefix?: string; text?: string }) {
  const t = useT();
  const [label, c] = badgeOf(k);
  return (
    <span className={`w-badge c-${c}`} data-badge={k}>
      {prefix}
      {text ?? t(label)}
    </span>
  );
}

export function BadgeText({ k, size = 12, suffix, style }: { k: string; size?: number; suffix?: string; style?: React.CSSProperties }) {
  const t = useT();
  const [label, c] = badgeOf(k);
  return (
    <span style={{ fontSize: size, color: colourVar(c), ...style }} data-badge={k}>
      {t(label)}
      {suffix}
    </span>
  );
}

/** A clock that re-renders every `ms`; shared by countdowns and relative times. */
export function useNow(ms = 1000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return now;
}

export function RelTime({ ts, style }: { ts: string; style?: React.CSSProperties }) {
  const t = useT();
  const now = useNow(30_000);
  return (
    <span title={fmtExact(ts)} style={style} suppressHydrationWarning>
      {fmtRel(ts, now, t)}
    </span>
  );
}

export function Countdown({ until, showClock }: { until: string; showClock?: boolean }) {
  const t = useT();
  const now = useNow();
  const ms = new Date(until).getTime() - now;
  const soon = ms < 5 * 60_000;
  return (
    <span
      className="mono"
      title={t("Expires at {time}", { time: fmtTime(until) })}
      style={{ fontSize: 12, color: soon ? "var(--color-warn)" : "var(--color-neutral-400)", whiteSpace: "nowrap" }}
      suppressHydrationWarning
    >
      {showClock ? t("Expires in {left} · {time}", { left: fmtCountdown(ms), time: fmtTime(until) }) : fmtCountdown(ms)}
    </span>
  );
}

export function Skeleton({ height, count = 3, gap = 12 }: { height: number; count?: number; gap?: number }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap }} aria-busy="true" data-testid="skeleton">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="card w-skel" style={{ height, animationDelay: `${i * 0.2}s` }} />
      ))}
    </div>
  );
}

export function Empty({ icon, title, text }: { icon?: React.ReactNode; title: string; text?: string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "48px 0", gap: 6, textAlign: "center" }}>
      {icon}
      <div style={{ fontSize: 17 }}>{title}</div>
      {text && <div style={{ fontSize: 14, color: "var(--color-neutral-400)" }}>{text}</div>}
    </div>
  );
}

export function Spinner({ size = 16 }: { size?: number }) {
  return <CircleNotch size={size} className="w-spin" />;
}

export function ErrorBox({ error }: { error: unknown }) {
  const t = useT();
  if (!error) return null;
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div role="alert" className="w-box w-box--danger" style={{ fontSize: 13 }}>
      <span style={{ color: "var(--color-danger)" }}>{t("Something went wrong")}</span>
      <span style={{ color: "var(--color-neutral-200)" }}>{msg}</span>
    </div>
  );
}

export function Page({ max, children, className, style }: { max: number; children: React.ReactNode; className?: string; style?: React.CSSProperties }) {
  return (
    <section className={`w-page ${className ?? ""}`} style={{ maxWidth: max, ...style }}>
      {children}
    </section>
  );
}

export function Header({ title, sub, children }: { title: string; sub?: React.ReactNode; children?: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 12, flexWrap: "wrap" }}>
      <div style={{ flex: 1, minWidth: 0 }}>
        <h2>{title}</h2>
        {sub && <div className="w-sub">{sub}</div>}
      </div>
      {children}
    </div>
  );
}

export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Clipboard can be blocked (insecure context, permissions); the toast still tells the user what we tried.
  }
}

export function Seg<K extends string>({
  name,
  value,
  options,
  onChange,
  style,
}: {
  name: string;
  value: K;
  options: { key: K; label: React.ReactNode; count?: number }[];
  onChange: (k: K) => void;
  style?: React.CSSProperties;
}) {
  return (
    <div className="seg" role="radiogroup" style={{ alignSelf: "flex-start", flexWrap: "wrap", ...style }}>
      {options.map((o) => (
        <label key={o.key} className="seg-opt" style={{ whiteSpace: "nowrap" }}>
          <input type="radio" name={name} checked={value === o.key} onChange={() => onChange(o.key)} />
          {o.label}
          {o.count != null && <span style={{ color: "var(--color-neutral-500)" }}>{o.count}</span>}
        </label>
      ))}
    </div>
  );
}

export function useDebounced<V>(value: V, ms = 250): V {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}
