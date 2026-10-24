"use client";
// Approvals (spec 3): pending plans oldest first, j / k to move, Enter to open; then recently decided.
import { ArrowRight, CheckCircle, GitDiff, Timer, Warning } from "@phosphor-icons/react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { anyDialogOpen } from "@/components/dialog";
import { Badge, BadgeText, Countdown, Empty, ErrorBox, Header, Page, planBadgeKey, RelTime, Skeleton } from "@/components/ui";
import { useT } from "@/lib/i18n";
import { agentWarn, isPending } from "@/lib/plan";
import { useApprovals } from "@/lib/queries";
import type { PlanSummary } from "@/lib/types";

export default function Approvals() {
  const t = useT();
  const router = useRouter();
  const q = useApprovals();
  const [sel, setSel] = useState(-1);
  const pending = (q.data?.plans ?? []).filter((p) => isPending(p.status));
  const decided = (q.data?.plans ?? []).filter((p) => !isPending(p.status));
  const open = (id: string) => router.push(`/plans/${encodeURIComponent(id)}?from=approvals`);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || anyDialogOpen() || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "j") setSel((s) => Math.min(pending.length - 1, s + 1));
      else if (e.key === "k") setSel((s) => Math.max(0, s - 1));
      else if (e.key === "Enter" && sel >= 0 && pending[sel] && el.tagName !== "BUTTON" && el.tagName !== "A") open(pending[sel].id);
      else return;
      e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  return (
    <Page max={960}>
      <Header
        title={t("Approvals")}
        sub={
          <>
            {t("Oldest first")} · <span className="mono">j</span> / <span className="mono">k</span> {t("to move, Enter to open")}
          </>
        }
      />
      <ErrorBox error={q.error && !q.data ? q.error : null} />
      {q.isPending ? (
        <Skeleton height={116} />
      ) : pending.length ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {pending.map((p, i) => (
            <Card key={p.id} p={p} selected={i === sel} onOpen={() => open(p.id)} />
          ))}
        </div>
      ) : (
        <Empty icon={<CheckCircle size={28} color="var(--color-neutral-500)" />} title={t("No plans waiting")} text={t("Claude hasn’t asked for anything.")} />
      )}
      {decided.length > 0 && (
        <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
          <h6 className="w-h6">{t("Recently decided")}</h6>
          {decided.map((p) => (
            <button
              key={p.id}
              className="w-row-btn"
              onClick={() => router.push(`/plans/${encodeURIComponent(p.id)}?from=approvals`)}
              style={{ display: "flex", gap: 12, padding: "9px 10px", borderRadius: "var(--radius-md)", fontSize: 14, alignItems: "baseline" }}
            >
              <BadgeText k={planBadgeKey(p)} style={{ minWidth: 104 }} />
              <span style={{ flex: 1, minWidth: 0 }}>{p.goal}</span>
              <span style={{ fontSize: 12, color: "var(--color-neutral-400)", whiteSpace: "nowrap" }}>
                {p.target} · <RelTime ts={p.decided_at ?? p.created_at} />
              </span>
            </button>
          ))}
          <button className="btn btn-ghost" style={{ fontSize: 13, alignSelf: "flex-start" }} onClick={() => router.push("/plans")}>
            {t("All plans")} <ArrowRight size={14} />
          </button>
        </div>
      )}
    </Page>
  );
}

function Card({ p, selected, onOpen }: { p: PlanSummary; selected: boolean; onOpen: () => void }) {
  const t = useT();
  const warn = agentWarn(p.target, p.agent, t);
  return (
    <button
      className="card"
      onClick={onOpen}
      data-plan={p.id}
      style={{ textAlign: "left", padding: "16px 18px", gap: 10, border: `1px solid ${selected ? "var(--color-accent-700)" : "transparent"}`, color: "inherit", font: "inherit", cursor: "pointer" }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: 16, width: "100%" }}>
        <span style={{ flex: 1, fontSize: 17, fontWeight: 500, lineHeight: 1.3, textWrap: "pretty" }}>{p.goal}</span>
        {p.status === "awaiting_approval" && (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
            <Timer size={13} color="var(--color-neutral-400)" />
            <Countdown until={p.expires_at} />
          </span>
        )}
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", fontSize: 13, color: "var(--color-neutral-400)" }}>
        <span style={{ color: "var(--color-neutral-200)" }}>{p.target}</span> · <span>{p.requested_by}</span> ·{" "}
        <span>{p.steps === 1 ? t("1 step") : t("{n} steps", { n: p.steps })}</span> · <RelTime ts={p.created_at} />
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        {p.risk && <Badge k={p.risk} />}
        <Badge k={p.final_verdict} prefix={`${t("Gatekeepers:")} `} />
        {p.revises && (
          <span style={{ fontSize: 12, color: "var(--color-accent-300)", display: "inline-flex", alignItems: "center", gap: 4 }}>
            <GitDiff size={13} /> {t("Revision of #{id}", { id: p.revises })}
            {p.changed_steps != null && ` · ${p.changed_steps === 1 ? t("1 changed step") : t("{n} changed steps", { n: p.changed_steps })}`}
          </span>
        )}
        {p.status === "reviewing" && <span style={{ fontSize: 12, color: "var(--color-accent-300)" }}>{t("◌ Re-reviewing your edits")}</span>}
      </div>
      {warn && (
        <div style={{ fontSize: 13, color: `var(--color-${warn.colour})`, display: "flex", gap: 6, alignItems: "flex-start" }}>
          <Warning size={15} style={{ flex: "none", marginTop: 2 }} />
          <span>{warn.text}</span>
        </div>
      )}
    </button>
  );
}
