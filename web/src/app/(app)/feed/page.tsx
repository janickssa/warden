"use client";
// Live feed (spec 6): everything Warden sees, newest first. New entries arrive over the socket.
import { CheckCircle, ClockClockwise, Eye, FileText, HardDrives, LockSimple, Play, Scales, ShieldCheck, StopCircle, Timer, XCircle } from "@phosphor-icons/react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ErrorBox, Header, Page, Seg, Skeleton } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtDate, fmtRel, fmtTime } from "@/lib/format";
import { N, useT } from "@/lib/i18n";
import { useStatus } from "@/lib/queries";
import type { Feed as FeedT, FeedItem } from "@/lib/types";

const TYPES: Record<string, [string, React.ComponentType<{ size?: number }>, string]> = {
  proposal: [N("Proposal"), FileText, "var(--color-accent-300)"],
  verdict: [N("Verdict"), Scales, "var(--color-neutral-200)"],
  approval: [N("Approval"), CheckCircle, "var(--color-ok)"],
  rejection: [N("Rejection"), XCircle, "var(--color-neutral-300)"],
  read_only: [N("Read-only"), Eye, "var(--color-neutral-300)"],
  run: [N("Run"), Play, "var(--color-accent-300)"],
  schedule: [N("Schedule"), ClockClockwise, "var(--color-neutral-200)"],
  kill: [N("Kill switch"), StopCircle, "var(--color-danger)"],
  expired: [N("Expired"), Timer, "var(--color-neutral-400)"],
  policy: [N("Policy"), ShieldCheck, "var(--color-accent-300)"],
  agent: [N("Agent"), HardDrives, "var(--color-neutral-200)"],
  lockdown: [N("Lockdown"), LockSimple, "var(--color-danger)"],
};
const FILTERS = [
  ["all", N("All")],
  ["proposal", N("Proposals")],
  ["verdict", N("Verdicts")],
  ["approval", N("Approvals")],
  ["read_only", N("Read-only")],
  ["run", N("Runs")],
  ["schedule", N("Schedules")],
  ["policy_agents", N("Policy & agents")],
] as const;
const CLIENTS = [
  ["all", N("All clients")],
  ["claude", N("Claude")],
  ["dashboard", N("Dashboard")],
  ["cli", N("CLI")],
  ["iphone", N("iPhone")],
  ["agent", N("Agents")],
  ["warden", N("Warden")],
] as const;
const COLS = "56px 110px 120px 52px minmax(0,1fr)";

/** Claude clients are named (`claude-code`); humans read `dashboard:alice`, agents `agent:dev`. */
const clientOf = (actor: string) => actor;

export default function Feed() {
  const t = useT();
  const router = useRouter();
  const status = useStatus();
  const [type, setType] = useState<string>("all");
  const [target, setTarget] = useState<string>("all");
  const [client, setClient] = useState<string>("all");
  const feed = useQuery({
    queryKey: ["feed", type, target, client],
    queryFn: () => api<FeedT>(`/feed?type=${type}&target=${encodeURIComponent(target)}&client=${client}`),
    placeholderData: keepPreviousData,
  });
  const targets = (status.data?.agents ?? []).map((a) => a.name);
  return (
    <Page max={1040}>
      <Header title={t("Live feed")} sub={t("Everything Warden sees, newest first")} />
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <Seg name="feed-type" value={type} onChange={setType} options={FILTERS.map(([k, l]) => ({ key: k, label: t(l) }))} />
        <Seg name="feed-target" value={target} onChange={setTarget} options={[{ key: "all", label: t("All targets") }, ...targets.map((n) => ({ key: n, label: n }))]} />
        <Seg name="feed-client" value={client} onChange={setClient} options={CLIENTS.map(([k, l]) => ({ key: k, label: t(l) }))} />
      </div>
      <ErrorBox error={feed.error && !feed.data ? feed.error : null} />
      {feed.isPending ? (
        <Skeleton height={40} gap={8} />
      ) : feed.data?.items.length ? (
        <div style={{ overflowX: "auto" }}>
          <div style={{ minWidth: 640 }}>
            {feed.data.items.map((i) => (
              <Row key={i.seq} i={i} onOpen={i.plan_id ? () => router.push(`/plans/${encodeURIComponent(i.plan_id!)}?from=feed`) : undefined} />
            ))}
          </div>
        </div>
      ) : (
        <div style={{ fontSize: 14, color: "var(--color-neutral-400)", padding: "16px 8px" }}>{t("Nothing matches these filters yet.")}</div>
      )}
    </Page>
  );
}

function Row({ i, onOpen }: { i: FeedItem; onOpen?: () => void }) {
  const t = useT();
  const [label, Icon, colour] = TYPES[i.type] ?? [i.type, FileText, "var(--color-neutral-300)"];
  const ro = i.type === "read_only";
  const Tag = onOpen ? "button" : "div";
  return (
    <Tag
      className={`w-row-rule${onOpen ? " w-row-btn" : ""}`}
      onClick={onOpen}
      style={{ display: "grid", gridTemplateColumns: COLS, gap: 12, alignItems: "baseline", padding: "10px 8px", fontSize: 14, width: "100%" }}
      data-feed={i.seq}
    >
      <span className="mono" style={{ fontSize: 12, color: "var(--color-neutral-400)" }} title={`${fmtDate(i.ts)} ${fmtTime(i.ts, true)} · ${fmtRel(i.ts, Date.now(), t)}`}>
        {fmtTime(i.ts)}
      </span>
      <span style={{ display: "inline-flex", gap: 6, fontSize: 12, color: colour, alignItems: "center" }}>
        <Icon size={14} /> {t(label)}
      </span>
      <span style={{ fontSize: 12, color: "var(--color-neutral-400)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={i.actor}>
        {clientOf(i.actor)}
      </span>
      <span style={{ fontSize: 12, color: "var(--color-neutral-300)" }}>{i.target ?? ""}</span>
      <span style={{ color: "var(--color-neutral-100)", wordBreak: "break-word", fontSize: 14 }}>
        <span className="mono" style={{ fontSize: 12, color: "var(--color-accent-300)" }}>{i.action}</span>{" "}
        <span className={ro ? "mono" : undefined} style={{ fontSize: ro ? 13 : 14 }}>{i.subject}</span>
      </span>
    </Tag>
  );
}
