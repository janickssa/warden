"use client";
// Plans (spec 4): every plan, newest first, with a status filter and search over goals, IDs and commands.
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { BadgeText, ErrorBox, Header, Page, planBadgeKey, RelTime, Seg, Skeleton, useDebounced } from "@/components/ui";
import { api } from "@/lib/api";
import { N, useT } from "@/lib/i18n";
import type { PlanList, PlanSummary } from "@/lib/types";

const FILTERS = [
  ["all", N("All")],
  ["awaiting", N("Awaiting")],
  ["approved_running", N("Approved & running")],
  ["succeeded", N("Succeeded")],
  ["failed", N("Failed")],
  ["invalidated", N("Invalidated")],
  ["closed", N("Rejected & expired")],
] as const;
type F = (typeof FILTERS)[number][0];
const COLS = "128px minmax(0,1fr) 52px 44px 110px 90px";

export default function Plans() {
  const t = useT();
  const router = useRouter();
  const [filter, setFilter] = useState<F>("all");
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim());
  const plans = useQuery({
    queryKey: ["plans", filter, q],
    queryFn: () => api<PlanList>(`/plans?filter=${filter}&q=${encodeURIComponent(q)}`),
    placeholderData: keepPreviousData,
  });
  return (
    <Page max={1100}>
      <Header title={t("Plans")} sub={t("Every plan Claude has proposed, newest first")}>
        <input className="input" style={{ maxWidth: 280 }} placeholder={t("Search goal, plan ID, command…")} value={search} onChange={(e) => setSearch(e.target.value)} aria-label={t("Search")} />
      </Header>
      <Seg name="plan-filter" value={filter} onChange={setFilter} options={FILTERS.map(([k, l]) => ({ key: k, label: t(l), count: plans.data?.counts[k] }))} />
      <ErrorBox error={plans.error && !plans.data ? plans.error : null} />
      <div style={{ overflowX: "auto" }}>
        <div style={{ minWidth: 720 }}>
          <div className="w-head-row" style={{ gridTemplateColumns: COLS }}>
            <span>{t("Status")}</span>
            <span>{t("Goal")}</span>
            <span>{t("Target")}</span>
            <span>{t("Steps")}</span>
            <span>{t("Requested by")}</span>
            <span>{t("Proposed")}</span>
          </div>
          {plans.isPending ? (
            <div style={{ paddingTop: 8 }}>
              <Skeleton height={44} gap={8} />
            </div>
          ) : plans.data?.plans.length ? (
            plans.data.plans.map((p) => <Row key={p.id} p={p} onOpen={() => router.push(`/plans/${encodeURIComponent(p.id)}?from=plans`)} />)
          ) : (
            <div style={{ fontSize: 14, color: "var(--color-neutral-400)", padding: "16px 8px" }}>{t("No plans match.")}</div>
          )}
        </div>
      </div>
    </Page>
  );
}

function Note({ p }: { p: PlanSummary }) {
  const t = useT();
  if (p.status === "failed" && p.failed_at != null) {
    const why = p.fail_reason && /^[a-z_]+$/.test(p.fail_reason) ? p.fail_reason : t("non-zero exit");
    return <span style={{ color: "var(--color-danger)" }}> · {t("{why} at step {n}", { why, n: p.failed_at })}</span>;
  }
  if (p.status === "invalidated" && p.invalidated_by != null) return <span style={{ color: "var(--color-warn)" }}> · {t("invalidated by policy v{v}", { v: p.invalidated_by })}</span>;
  if (p.revises) return <span style={{ color: "var(--color-neutral-400)" }}> · {t("revises {id}", { id: p.revises })}</span>;
  return null;
}

function Row({ p, onOpen }: { p: PlanSummary; onOpen: () => void }) {
  return (
    <button className="w-row-btn w-row-rule" onClick={onOpen} data-plan={p.id} style={{ display: "grid", gridTemplateColumns: COLS, gap: 12, padding: "10px 8px", alignItems: "baseline", width: "100%" }}>
      <BadgeText k={planBadgeKey(p)} />
      <span style={{ minWidth: 0 }}>
        <span style={{ fontSize: 14, display: "block" }}>{p.goal}</span>
        <span className="mono" style={{ fontSize: 11.5, color: "var(--color-neutral-500)" }}>
          {p.id}
          <Note p={p} />
        </span>
      </span>
      <span style={{ fontSize: 13, color: "var(--color-neutral-200)" }}>{p.target}</span>
      <span style={{ fontSize: 13, color: "var(--color-neutral-300)" }}>{p.steps}</span>
      <span style={{ fontSize: 12, color: "var(--color-neutral-400)", overflow: "hidden", textOverflow: "ellipsis" }}>{p.requested_by}</span>
      <RelTime ts={p.created_at} style={{ fontSize: 12, color: "var(--color-neutral-400)" }} />
    </button>
  );
}
