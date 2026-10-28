"use client";
// Schedules (spec 7, README 11): plan templates approved once, with their scope and last result.
import { ClockClockwise } from "@phosphor-icons/react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { ScheduleState, useNextRun } from "@/components/schedule-ui";
import { Empty, ErrorBox, Header, Page, Skeleton } from "@/components/ui";
import { api } from "@/lib/api";
import { describeCron } from "@/lib/cron";
import { fmtDate } from "@/lib/format";
import { useT } from "@/lib/i18n";
import type { ScheduleView } from "@/lib/types";

const COLS = "minmax(140px,1.2fr) 80px minmax(150px,1.3fr) 130px minmax(120px,1fr) 96px 110px";

export default function Schedules() {
  const t = useT();
  const router = useRouter();
  const next = useNextRun();
  const q = useQuery({ queryKey: ["schedules"], queryFn: () => api<ScheduleView[]>("/schedules") });
  return (
    <Page max={1100}>
      <Header title={t("Schedules")} sub={t("Plan templates you approved once. Any change needs a new approval. Times are Europe/Copenhagen.")} />
      <ErrorBox error={q.error && !q.data ? q.error : null} />
      {q.isPending ? (
        <Skeleton height={44} gap={8} />
      ) : !q.data?.length ? (
        <Empty
          icon={<ClockClockwise size={28} color="var(--color-neutral-500)" />}
          title={t("No schedules yet")}
          text={t("Open a plan that succeeded and choose Save as schedule. Each schedule needs its own approval.")}
        />
      ) : (
        <div style={{ overflowX: "auto" }}>
          <div style={{ minWidth: 860 }}>
            <div className="w-head-row" style={{ gridTemplateColumns: COLS }}>
              <span>{t("Name")}</span>
              <span>{t("Target")}</span>
              <span>{t("When")}</span>
              <span>{t("Next run")}</span>
              <span>{t("Last result")}</span>
              <span>{t("Expires")}</span>
              <span>{t("State")}</span>
            </div>
            {q.data.map((s) => (
              <button
                key={s.id}
                className="w-row-btn w-row-rule"
                data-schedule={s.name}
                onClick={() => router.push(`/schedules/${encodeURIComponent(s.id)}`)}
                style={{ display: "grid", gridTemplateColumns: COLS, gap: 12, padding: "10px 8px", alignItems: "baseline", width: "100%" }}
              >
                <span className="mono" style={{ fontSize: 13, overflow: "hidden", textOverflow: "ellipsis" }}>{s.name}</span>
                <span style={{ fontSize: 13, color: "var(--color-neutral-200)" }}>{s.target}</span>
                <span style={{ fontSize: 14 }}>
                  {describeCron(s.cron, t)}
                  <span className="mono" style={{ display: "block", fontSize: 11, color: "var(--color-neutral-500)" }}>{s.cron}</span>
                </span>
                <span style={{ fontSize: 13, color: "var(--color-neutral-300)" }}>{next(s.next_run)}</span>
                <span>
                  {s.last_result ? (
                    <>
                      <span style={{ fontSize: 13, color: s.last_result === "succeeded" ? "var(--color-ok)" : s.last_result === "failed" ? "var(--color-danger)" : "var(--color-warn)" }}>
                        {s.last_result === "succeeded" ? t("✓ Succeeded") : s.last_result === "failed" ? t("✕ Failed") : t("○ Missed")}
                      </span>
                      {s.last_detail && <span style={{ display: "block", fontSize: 12, color: "var(--color-neutral-400)" }}>{s.last_detail}</span>}
                    </>
                  ) : (
                    <span style={{ fontSize: 13, color: "var(--color-neutral-500)" }}>—</span>
                  )}
                </span>
                <span style={{ fontSize: 13, color: "var(--color-neutral-300)" }}>{s.expires_at ? fmtDate(s.expires_at) : "—"}</span>
                <span>
                  <ScheduleState status={s.status} />
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
    </Page>
  );
}
