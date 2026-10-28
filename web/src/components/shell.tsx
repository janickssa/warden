"use client";
// App shell (spec 1, 13, 14): sidebar, top bar with agent pills and gatekeepers, the global banners,
// Lockdown and the kill switch. `<main>` is the scroll container; the plan page's scroll gate relies on it.
import {
  ClockClockwise,
  Desktop,
  Fingerprint,
  GearSix,
  HardDrives,
  Key,
  ListChecks,
  LockSimple,
  Pulse,
  Scroll,
  ShieldCheck,
  SquaresFour,
  StopCircle,
  Tray,
  WifiSlash,
} from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { createContext, useContext, useEffect, useRef, useState } from "react";
import { api, ApiError, post } from "@/lib/api";
import { fmtTime } from "@/lib/format";
import { N, useT } from "@/lib/i18n";
import { useLive } from "@/lib/live";
import { useOffline, usePhone, usePlan, usePlans, useStatus } from "@/lib/queries";
import { useToast } from "@/lib/toast";
import type { AgentView, PlanDetail, PublishResult } from "@/lib/types";
import { anyDialogOpen, Dialog } from "./dialog";
import { confirmOptions, isCancel, usePasskey } from "./passkey";
import { SignatureDialog } from "./signature";

const MainCtx = createContext<React.RefObject<HTMLElement | null> | null>(null);
export const useMain = () => useContext(MainCtx)!;

export const NAV = [
  { key: "approvals", href: "/approvals", label: N("Approvals"), Icon: Tray },
  { key: "plans", href: "/plans", label: N("Plans"), Icon: ListChecks },
  { key: "feed", href: "/feed", label: N("Live feed"), Icon: Pulse },
  { key: "schedules", href: "/schedules", label: N("Schedules"), Icon: ClockClockwise },
  { key: "agents", href: "/agents", label: N("Agents"), Icon: HardDrives },
  { key: "groups", href: "/groups", label: N("Groups"), Icon: SquaresFour },
  { key: "policy", href: "/policy", label: N("Policy"), Icon: ShieldCheck },
  { key: "audit", href: "/audit", label: N("Audit log"), Icon: Scroll },
  { key: "settings", href: "/settings", label: N("Settings"), Icon: GearSix },
] as const;

/** Bug 1 fix: a plan page belongs to a plan list. Approvals when opened from there (or pending), else Plans. */
export const BACK: Record<string, [string, string]> = {
  approvals: ["/approvals", N("Approvals")],
  plans: ["/plans", N("Plans")],
  audit: ["/audit", N("Audit log")],
  feed: ["/feed", N("Live feed")],
};
export function planOrigin(from: string | null, status: string | undefined): string {
  if (from && from in BACK) return from;
  return status === "awaiting_approval" || status === "reviewing" ? "approvals" : "plans";
}

function useSection(): string {
  const path = usePathname();
  const params = useSearchParams();
  const planId = path.startsWith("/plans/") ? decodeURIComponent(path.slice(7)) : undefined;
  const plan = usePlan(planId);
  if (planId) {
    const o = planOrigin(params.get("from"), plan.data?.status);
    return o === "approvals" ? "approvals" : "plans"; // feed and audit are back targets, not plan lists
  }
  return path.split("/")[1] || "approvals";
}

export function Shell({ children }: { children: React.ReactNode }) {
  const t = useT();
  const phone = usePhone();
  const section = useSection();
  const path = usePathname();
  const router = useRouter();
  const main = useRef<HTMLElement>(null);
  const [dialog, setDialog] = useState<null | "keys" | "kill" | "lockdown" | "lift">(null);
  const status = useStatus();

  useEffect(() => {
    main.current?.scrollTo({ top: 0 });
    setDialog(null);
  }, [path]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable) return;
      if (e.key === "?" && !anyDialogOpen()) {
        e.preventDefault();
        setDialog("keys");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const phoneOk = section === "approvals" || path.startsWith("/plans/");
  const label = NAV.find((n) => n.key === section)?.label ?? "Approvals";

  return (
    <MainCtx.Provider value={main}>
      <div style={{ display: "grid", gridTemplateColumns: phone ? "minmax(0,1fr)" : "232px minmax(0,1fr)", height: "100dvh", color: "var(--color-text)", background: "var(--color-bg)" }}>
        {!phone && <Sidebar section={section} onKeys={() => setDialog("keys")} />}
        <div style={{ display: "flex", flexDirection: "column", minWidth: 0, minHeight: 0 }}>
          {phone ? <PhoneHeader open={setDialog} /> : <TopBar open={setDialog} />}
          <Banners onLift={() => setDialog("lift")} />
          <main ref={main} style={{ flex: 1, overflow: "auto", position: "relative" }} id="main">
            {phone && !phoneOk ? (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center", padding: "48px 20px", gap: 8 }}>
                <Desktop size={28} color="var(--color-neutral-500)" />
                <div style={{ fontSize: 17 }}>{t("{page} isn’t available in a phone browser", { page: t(label) })}</div>
                <div style={{ fontSize: 14, color: "var(--color-neutral-400)" }}>{t("Use the desktop dashboard or the Warden app.")}</div>
                <button className="btn btn-secondary" style={{ minHeight: 44, marginTop: 8 }} onClick={() => router.push("/approvals")}>
                  <Tray size={17} /> {t("Go to Approvals")}
                </button>
              </div>
            ) : (
              children
            )}
          </main>
        </div>
      </div>
      {dialog === "keys" && <ShortcutsDialog onClose={() => setDialog(null)} />}
      {dialog === "kill" && status.data?.running[0] && <KillDialog planId={status.data.running[0]} onClose={() => setDialog(null)} />}
      {dialog === "lockdown" && <LockdownDialog onClose={() => setDialog(null)} />}
      {dialog === "lift" && <LiftFlow onClose={() => setDialog(null)} />}
    </MainCtx.Provider>
  );
}

function Sidebar({ section, onKeys }: { section: string; onKeys: () => void }) {
  const t = useT();
  const status = useStatus();
  const qc = useQueryClient();
  const signOut = async () => {
    try {
      await post("/auth/logout");
    } finally {
      qc.clear();
      location.assign("/sign-in?signed_out=1");
    }
  };
  return (
    <aside
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "var(--space-6)",
        padding: "var(--space-6) var(--space-3)",
        background: "linear-gradient(180deg, var(--color-surface), var(--color-bg) 70%)",
        borderRight: "1px solid var(--color-divider)",
        overflow: "auto",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "0 10px" }}>
        <ShieldCheck size={21} color="var(--color-accent)" />
        <span style={{ fontSize: 17, fontWeight: 500, letterSpacing: "-0.01em" }}>Warden</span>
      </div>
      <nav style={{ display: "flex", flexDirection: "column", gap: 2 }} aria-label={t("Main")}>
        {NAV.map(({ key, href, label, Icon }) => (
          <Link key={key} href={href} className="w-nav-btn" aria-current={section === key ? "page" : undefined} data-nav={key}>
            <Icon size={17} />
            <span style={{ flex: 1 }}>{t(label)}</span>
            {key === "approvals" && !!status.data?.awaiting && (
              <span className="tag tag-accent" style={{ padding: "1px 7px" }} data-testid="approvals-count">
                {status.data.awaiting}
              </span>
            )}
            {key === "schedules" && !!status.data?.schedules_awaiting && (
              <span className="tag tag-accent" style={{ padding: "1px 7px" }} data-testid="schedules-count" title={t("Schedules waiting for your approval")}>
                {status.data.schedules_awaiting}
              </span>
            )}
          </Link>
        ))}
      </nav>
      <div style={{ marginTop: "auto", display: "flex", flexDirection: "column", gap: 6, padding: "0 10px", fontSize: 12, color: "var(--color-neutral-500)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <Fingerprint size={15} />
          <span style={{ flex: 1 }} title={status.data?.me}>
            {t("Signed in with passkey")}
          </span>
          <button className="btn btn-ghost" style={{ fontSize: 12, padding: "1px 6px" }} onClick={signOut}>
            {t("Sign out")}
          </button>
        </div>
        <button className="btn btn-ghost" style={{ fontSize: 12, padding: "2px 0", justifyContent: "flex-start" }} onClick={onKeys}>
          {t("? Keyboard shortcuts")}
        </button>
      </div>
    </aside>
  );
}

type PillState = "current" | "behind" | "offline";
function pillFor(members: AgentView[], latest: number, t: (s: string, v?: Record<string, string | number>) => string, group: boolean) {
  const off = members.filter((a) => a.status === "offline" || a.status === "revoked");
  const behind = members.filter((a) => a.status === "behind");
  const state: PillState = off.length ? "offline" : behind.length ? "behind" : "current";
  let label: string;
  if (group) label = off.length ? t("{n} offline", { n: off.length }) : behind.length ? t("{n} behind", { n: behind.length }) : `v${latest}`;
  else label = off.length ? t("offline") : `v${members[0]?.policy_version ?? "?"}`;
  const title = members.map((a) => `${a.name}: ${a.status === "online" ? "current" : a.status} · v${a.policy_version ?? "?"}`).join("\n");
  return { state, label, title };
}

function TopBar({ open }: { open: (d: "kill" | "lockdown") => void }) {
  const t = useT();
  const router = useRouter();
  const status = useStatus();
  const offline = useOffline();
  const live = useLive();
  const s = status.data;
  const agents = (s?.agents ?? []).filter((a) => a.status !== "not_enrolled");
  const groups = new Map<string, AgentView[]>();
  for (const a of agents) for (const g of a.groups) groups.set(g, [...(groups.get(g) ?? []), a]);
  const pills = [
    ...[...groups.entries()].map(([name, m]) => ({ name, ...pillFor(m, s?.policy_version ?? 0, t, true) })),
    ...agents.filter((a) => !a.groups.length).map((a) => ({ name: a.name, ...pillFor([a], s?.policy_version ?? 0, t, false) })),
  ];
  const colour = { current: "var(--color-ok)", behind: "var(--color-warn)", offline: "var(--color-danger)" };
  const icon = { current: "●", behind: "⏳", offline: "■" };
  return (
    <header style={{ display: "flex", alignItems: "center", gap: "var(--space-4)", padding: "10px 24px", borderBottom: "1px solid var(--color-divider)", flexWrap: "wrap" }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {pills.map((p) => (
          <button
            key={p.name}
            className="w-pill"
            title={p.title}
            onClick={() => router.push("/agents")}
            data-pill={p.name}
            style={{
              color: p.state === "current" ? "var(--color-neutral-200)" : colour[p.state],
              borderColor: p.state === "current" ? "var(--color-divider)" : `color-mix(in srgb, ${colour[p.state]} 45%, transparent)`,
            }}
          >
            <span style={{ color: colour[p.state] }}>{icon[p.state]}</span>
            {p.name}
            <span className="mono">{p.label}</span>
          </button>
        ))}
      </div>
      {pills.length > 0 && <span style={{ width: 1, height: 18, background: "var(--color-divider)" }} />}
      <div style={{ display: "flex", gap: 6, fontSize: 12, color: "var(--color-neutral-400)", alignItems: "center" }} data-testid="gatekeepers">
        {t("Gatekeepers")}
        {(s?.gatekeepers ?? []).map((g) => {
          const down = g.state === "unavailable";
          const title =
            g.state === "up"
              ? t("{name} online", { name: g.name })
              : down
                ? t("{name} unavailable · {why} · counted as escalate", { name: g.name, why: g.why ?? t("no answer") })
                : t("{name} · not asked yet", { name: g.name });
          return (
            <span key={g.name} title={title} style={{ display: "inline-flex", gap: 4, color: down ? "var(--color-warn)" : "var(--color-neutral-200)" }}>
              {g.name}
              <span style={{ color: down ? "var(--color-warn)" : g.state === "up" ? "var(--color-ok)" : "var(--color-neutral-500)" }}>{down || g.state === "unknown" ? "○" : "●"}</span>
            </span>
          );
        })}
        {s && !s.gatekeepers.length && <span style={{ color: "var(--color-warn)" }}>{t("none configured")}</span>}
      </div>
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10 }}>
        {offline && (
          <span style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>
            {t("Stale · last updated {time}", { time: fmtTime(live.lastSeen) })}
          </span>
        )}
        {s && !s.lockdown && (
          <button
            className="btn btn-secondary"
            style={{ fontSize: 13, color: "var(--color-danger)" }}
            title={t("Kill running plans and allow read-only commands only")}
            disabled={offline}
            onClick={() => open("lockdown")}
          >
            <LockSimple size={16} /> {t("Lockdown")}
          </button>
        )}
        {!!s?.running.length && (
          <button className="btn w-btn-danger" disabled={offline} onClick={() => open("kill")}>
            <StopCircle size={16} weight="fill" /> {t("Kill switch")}
          </button>
        )}
      </div>
    </header>
  );
}

function PhoneHeader({ open }: { open: (d: "kill" | "lockdown") => void }) {
  const t = useT();
  const router = useRouter();
  const status = useStatus();
  const offline = useOffline();
  const s = status.data;
  return (
    <header style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 16px", borderBottom: "1px solid var(--color-divider)" }}>
      <button className="w-row-btn" style={{ display: "flex", alignItems: "center", gap: 8, padding: 0 }} onClick={() => router.push("/approvals")}>
        <ShieldCheck size={21} color="var(--color-accent)" />
        <span style={{ fontSize: 17, fontWeight: 500 }}>Warden</span>
        {!!s?.awaiting && (
          <span className="tag tag-accent" style={{ padding: "1px 7px" }}>
            {s.awaiting}
          </span>
        )}
      </button>
      <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
        {!!s?.running.length && (
          <button className="btn w-btn-danger" style={{ minHeight: 44 }} disabled={offline} onClick={() => open("kill")}>
            <StopCircle size={16} weight="fill" /> {t("Kill")}
          </button>
        )}
        {s && !s.lockdown && (
          <button className="btn btn-secondary" style={{ minHeight: 44, color: "var(--color-danger)" }} disabled={offline} onClick={() => open("lockdown")}>
            <LockSimple size={16} /> {t("Lockdown")}
          </button>
        )}
      </div>
    </header>
  );
}

function Banners({ onLift }: { onLift: () => void }) {
  const t = useT();
  const toast = useToast();
  const live = useLive();
  const offline = useOffline();
  const status = useStatus();
  const [retrying, setRetrying] = useState(false);
  const s = status.data;
  const retry = () => {
    setRetrying(true);
    live.retry();
    setTimeout(async () => {
      setRetrying(false);
      try {
        await api("/status");
      } catch {
        toast(t("Still can’t reach Warden"), "bad");
      }
    }, 1200);
  };
  const row: React.CSSProperties = { display: "flex", alignItems: "center", gap: 12, padding: "10px 24px", fontSize: 14, flexWrap: "wrap" };
  return (
    <>
      {offline && (
        <div role="alert" data-testid="offline-banner" style={{ ...row, background: "color-mix(in srgb, var(--color-warn) 12%, transparent)", borderBottom: "1px solid color-mix(in srgb, var(--color-warn) 35%, transparent)" }}>
          <WifiSlash size={18} color="var(--color-warn)" />
          <span style={{ flex: 1 }}>
            {t("Can’t reach Warden. Is WireGuard connected?")}{" "}
            <span style={{ color: "var(--color-neutral-400)" }}>{t("Showing cached data, read-only.")}</span>
          </span>
          <button className="btn btn-secondary" style={{ fontSize: 13 }} onClick={retry} disabled={retrying}>
            {retrying ? t("Retrying…") : t("Retry")}
          </button>
        </div>
      )}
      {s?.lockdown && (
        <div role="alert" data-testid="lockdown-banner" style={{ ...row, background: "color-mix(in srgb, var(--color-danger) 14%, transparent)", borderBottom: "1px solid color-mix(in srgb, var(--color-danger) 40%, transparent)" }}>
          <LockSimple size={18} weight="fill" color="var(--color-danger)" />
          <span style={{ flex: 1 }}>
            <span style={{ color: "var(--color-danger)" }}>{t("■ Lockdown active")}</span>{" "}
            {t("· every agent allows read-only commands only (policy v{v}). Plans can be reviewed and approved, not run.", { v: s.policy_version })}
          </span>
          {s.pending_publish == null && (
            <button className="btn btn-secondary" style={{ fontSize: 13 }} disabled={offline} onClick={onLift}>
              <Key size={16} /> {t("Lift lockdown…")}
            </button>
          )}
        </div>
      )}
    </>
  );
}

export function ShortcutsDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const rows: [string, string][] = [
    ["j / k", N("Move through lists")],
    ["Enter", N("Open selected plan")],
    ["r", N("Reject the open plan")],
    ["?", N("Show this list")],
    ["Esc", N("Close dialogs")],
  ];
  return (
    <Dialog title={t("Keyboard shortcuts")} onClose={onClose} backdropClose actions={<button className="btn btn-secondary" onClick={onClose}>{t("Close")}</button>}>
      <div style={{ display: "grid", gridTemplateColumns: "80px 1fr", gap: "8px 12px", fontSize: 14 }}>
        {rows.map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <span className="mono" style={{ color: "var(--color-accent-300)" }}>{k}</span>
            <span>{t(v)}</span>
          </div>
        ))}
      </div>
      <div className="dialog-body" style={{ fontSize: 13, color: "var(--color-neutral-400)" }}>
        {t("There is deliberately no shortcut for Approve.")}
      </div>
    </Dialog>
  );
}

export function KillDialog({ planId, onClose }: { planId: string; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const plan = usePlan(planId);
  const [busy, setBusy] = useState(false);
  const p: PlanDetail | undefined = plan.data;
  const step = p?.step_list.find((s) => s.status === "running")?.n ?? 1;
  const stop = async () => {
    setBusy(true);
    try {
      await post(`/plans/${encodeURIComponent(planId)}/kill`);
      toast(t("Kill switch used · plan cancelled"), "bad");
      onClose();
    } catch (e) {
      toast((e as Error).message, "bad");
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={
        <>
          <StopCircle size={22} weight="fill" color="var(--color-danger)" /> {t("Stop the running plan?")}
        </>
      }
      onClose={onClose}
      backdropClose
      busy={busy}
      testId="kill-dialog"
      actions={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
            {t("Keep running")}
          </button>
          <button className="btn w-btn-danger" onClick={stop} disabled={busy}>
            {t("Stop now")}
          </button>
        </>
      }
    >
      <div className="dialog-body">
        {t("Sends SIGTERM to step {n} of {id} on {target}, then SIGKILL after 10 s. Remaining steps are skipped and the plan can’t be resumed.", {
          n: step,
          id: planId,
          target: p?.target ?? "…",
        })}
      </div>
    </Dialog>
  );
}

/** README 17.1(5): stopping everything takes deliberate effort, so Lockdown is a 2 s press-and-hold. */
export function HoldButton({ label, onDone, disabled }: { label: string; onDone: () => void; disabled?: boolean }) {
  const t = useT();
  const [p, setP] = useState(0);
  const start = useRef<number | null>(null);
  const raf = useRef<number | null>(null);
  const HOLD = 2000;
  const tick = () => {
    if (start.current == null) return;
    const v = Math.min(1, (performance.now() - start.current) / HOLD);
    setP(v);
    if (v >= 1) {
      start.current = null;
      setP(0);
      onDone();
    } else raf.current = requestAnimationFrame(tick);
  };
  const begin = () => {
    if (disabled || start.current != null) return;
    start.current = performance.now();
    raf.current = requestAnimationFrame(tick);
  };
  const end = () => {
    start.current = null;
    if (raf.current) cancelAnimationFrame(raf.current);
    setP(0);
  };
  useEffect(() => end, []); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <button
      type="button"
      disabled={disabled}
      data-testid="hold-button"
      onPointerDown={begin}
      onPointerUp={end}
      onPointerLeave={end}
      onKeyDown={(e) => {
        if ((e.key === " " || e.key === "Enter") && !e.repeat) {
          e.preventDefault();
          begin();
        }
      }}
      onKeyUp={(e) => {
        if (e.key === " " || e.key === "Enter") end();
      }}
      onContextMenu={(e) => e.preventDefault()}
      style={{
        position: "relative",
        overflow: "hidden",
        minHeight: 48,
        borderRadius: "var(--radius-md)",
        border: "1px solid var(--color-danger)",
        background: "transparent",
        color: "var(--color-danger)",
        fontSize: 15,
        userSelect: "none",
        touchAction: "none",
        cursor: "pointer",
        fontFamily: "inherit",
      }}
    >
      <span style={{ position: "absolute", left: 0, top: 0, bottom: 0, width: `${p * 100}%`, background: "color-mix(in srgb, var(--color-danger) 28%, transparent)" }} />
      <span style={{ position: "relative", display: "inline-flex", alignItems: "center", gap: 8 }}>
        <LockSimple size={18} weight="fill" />
        {p > 0 ? t("Keep holding… {s} s", { s: ((HOLD * (1 - p)) / 1000).toFixed(1) }) : label}
      </span>
    </button>
  );
}

export function LockdownDialog({ onClose }: { onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const passkey = usePasskey();
  const status = useStatus();
  const plans = usePlans();
  const offline = useOffline();
  const s = status.data;
  const running = s?.running.length ?? 0;
  const approved = (plans.data?.plans ?? []).filter((p) => p.status === "approved" && !p.held_reason).length;
  const online = (s?.agents ?? []).filter((a) => a.online).length;
  const go = async () => {
    try {
      await passkey({
        title: t("Confirm lockdown with your passkey"),
        body: t("Running plans are killed and every agent gets a read-only bundle. Lifting needs the offline key."),
        options: () => confirmOptions("lockdown"),
        submit: (signed) => post<PublishResult>("/lockdown", signed),
      });
      toast(t("Lockdown active · every agent is read-only"), "bad");
      qc.invalidateQueries();
      onClose();
    } catch (e) {
      if (!isCancel(e)) toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
    }
  };
  return (
    <Dialog
      title={
        <>
          <LockSimple size={22} weight="fill" color="var(--color-danger)" /> {t("Lock down every agent?")}
        </>
      }
      onClose={onClose}
      backdropClose
      testId="lockdown-dialog"
      actions={
        <button className="btn btn-secondary" onClick={onClose}>
          {t("Cancel")}
        </button>
      }
    >
      <div className="dialog-body">
        {t("Publishes a tightening bundle that allows only read-only commands on every agent. Lifting it later counts as loosening and needs the offline key.")}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 13, color: "var(--color-neutral-300)" }}>
        <span>· {running === 1 ? t("1 running plan killed now") : t("{n} running plans killed now", { n: running })}</span>
        <span>· {approved === 1 ? t("1 approved plan held until it’s lifted") : t("{n} approved plans held until it’s lifted", { n: approved })}</span>
        <span>· {t("Policy v{v} pushed to {n} online agent(s)", { v: (s?.policy_version ?? 0) + 1, n: online })}</span>
        <span>· {t("Read-only commands keep working, so Claude can still investigate")}</span>
      </div>
      <HoldButton label={t("Press and hold for 2 s")} onDone={go} disabled={offline} />
    </Dialog>
  );
}

/** Lift: create the pending loosening bundle, then the offline signature upload. */
export function LiftFlow({ onClose }: { onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const [version, setVersion] = useState<number | null>(null);
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    post<PublishResult>("/lockdown/lift")
      .then((r) => {
        qc.invalidateQueries();
        if (r.outcome === "pending") setVersion(r.version);
        else {
          toast(t("Lockdown lifted · v{v} rolling out", { v: r.version }));
          onClose();
        }
      })
      .catch((e) => {
        toast((e as Error).message, "bad");
        onClose();
      });
  }, [qc, toast, t, onClose]);
  return version == null ? null : <SignatureDialog mode="lift" version={version} onClose={onClose} />;
}
