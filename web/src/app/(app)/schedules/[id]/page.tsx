"use client";
// One schedule: exactly what it runs, its scope, and the decision. Approving is a standing approval, so it
// always takes the passkey, and only after scrolling past every command (as for a plan).
import { ArrowLeft, Fingerprint, Pause, Play, Trash } from "@phosphor-icons/react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useCallback, useEffect, useLayoutEffect, useState } from "react";
import { Dialog } from "@/components/dialog";
import { isCancel, usePasskey } from "@/components/passkey";
import { ScheduleState, useNextRun } from "@/components/schedule-ui";
import { useMain } from "@/components/shell";
import { Badge, BadgeText, ErrorBox, planBadgeKey, RelTime, Skeleton } from "@/components/ui";
import { api, ApiError, post } from "@/lib/api";
import { describeCron } from "@/lib/cron";
import { fmtDur, fmtExact } from "@/lib/format";
import { useT } from "@/lib/i18n";
import { shortHash } from "@/lib/plan";
import { useOffline } from "@/lib/queries";
import { useToast } from "@/lib/toast";
import type { ApproveOptions, ScheduleDetail } from "@/lib/types";

export default function SchedulePage() {
  const { id } = useParams<{ id: string }>();
  const sid = decodeURIComponent(id);
  const q = useQuery({ queryKey: ["schedule", sid], queryFn: () => api<ScheduleDetail>(`/schedules/${encodeURIComponent(sid)}`) });
  if (q.error && !q.data) return <section className="w-page" style={{ maxWidth: 1040 }}><ErrorBox error={q.error} /></section>;
  if (!q.data) return <section className="w-page" style={{ maxWidth: 1040 }}><Skeleton height={80} /></section>;
  return <Schedule s={q.data} />;
}

function Schedule({ s }: { s: ScheduleDetail }) {
  const t = useT();
  const toast = useToast();
  const router = useRouter();
  const qc = useQueryClient();
  const passkey = usePasskey();
  const offline = useOffline();
  const main = useMain();
  const next = useNextRun();
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const awaiting = s.status === "awaiting_approval";
  const path = `/schedules/${encodeURIComponent(s.id)}`;

  const check = useCallback(() => {
    const m = main.current;
    if (!m || !awaiting || reviewed) return;
    if (m.scrollTop + m.clientHeight >= m.scrollHeight - 24) setReviewed(true);
  }, [main, awaiting, reviewed]);
  useLayoutEffect(() => check());
  useEffect(() => {
    const m = main.current;
    m?.addEventListener("scroll", check, { passive: true });
    return () => m?.removeEventListener("scroll", check);
  }, [main, check]);

  const act = async (what: "pause" | "resume") => {
    setBusy(true);
    try {
      await post(`${path}/${what}`);
      toast(what === "pause" ? t("{name} paused · it doesn’t run until you resume it", { name: s.name }) : t("{name} resumed · it runs from the next slot", { name: s.name }), "neutral");
      qc.invalidateQueries();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
    } finally {
      setBusy(false);
    }
  };

  const approve = async () => {
    setBusy(true);
    try {
      await passkey({
        title: t("Approve schedule {name} with your passkey", { name: s.name }),
        body: t("Your passkey signs these {n} steps for {target}, {when}, until {date}. {target}’s agent checks your signature and the time before every run.", {
          n: s.step_list.length,
          target: s.target,
          when: describeCron(s.cron, t).toLowerCase(),
          date: fmtExact(new Date(Date.now() + s.expiry_days * 86_400_000)),
        }),
        options: async () => {
          const o = await post<ApproveOptions>(`${path}/approval/options`);
          return { challenge_id: o.challenge_id!, options: o.options! };
        },
        submit: (signed) => post<ScheduleDetail>(`${path}/approve`, signed),
      });
      toast(t("Schedule {name} approved · agents check your signature before every run", { name: s.name }));
      qc.invalidateQueries();
    } catch (e) {
      if (!isCancel(e)) toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
    } finally {
      setBusy(false);
    }
  };

  const info: Record<string, string> = {
    active: t("Runs {when} · next run {next}", { when: describeCron(s.cron, t).toLowerCase(), next: next(s.next_run) }),
    paused: t("Paused · it doesn’t run until you resume it"),
    stopped: t("■ Stopped: {reason}. Claude can propose a fix; save the working plan as a new schedule.", { reason: s.status_reason ?? "" }),
    expired: t("— Expired. Save a plan as a new schedule to keep running it."),
    invalidated: t("⊘ The current policy denies these steps: {reason}", { reason: s.status_reason ?? "" }),
  };

  return (
    <section className="w-page has-actionbar" style={{ maxWidth: 1040, paddingTop: 20, gap: "var(--space-8)" }}>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <Link href="/schedules" className="btn btn-ghost" style={{ fontSize: 13, alignSelf: "flex-start" }}>
          <ArrowLeft size={14} /> {t("Schedules")}
        </Link>
        <h1 className="mono" style={{ fontSize: 28, margin: 0 }}>{s.name}</h1>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", fontSize: 13, color: "var(--color-neutral-400)" }}>
          <ScheduleState status={s.status} />
          {s.risk && <Badge k={s.risk} />}
          <span style={{ color: "var(--color-neutral-200)" }}>{s.target}</span> · <span>{describeCron(s.cron, t)}</span> ·{" "}
          <span className="mono" style={{ fontSize: 12 }}>{s.cron}</span> · <span>Europe/Copenhagen</span>
        </div>
        <div style={{ fontSize: 14, color: "var(--color-neutral-300)" }}>{s.goal}</div>
      </div>

      <div className="card elev-sm" style={{ padding: "12px 16px", gap: 8 }} data-testid="schedule-scope">
        <h6 className="w-h6">{t("Scope")}</h6>
        <div style={{ display: "grid", gridTemplateColumns: "160px minmax(0,1fr)", gap: "6px 16px", fontSize: 13 }}>
          {(
            [
              [t("Template hash"), <span key="h" className="mono" title={s.template_hash}>{shortHash(s.template_hash)}</span>],
              [t("From plan"), <Link key="p" className="mono" href={`/plans/${encodeURIComponent(s.source_plan)}?from=plans`}>{s.source_plan}</Link>],
              [t("Created"), `${s.created_by} · ${fmtExact(s.created_at)}`],
              [t("Approved"), s.approved_at ? `${s.approved_by} · ${fmtExact(s.approved_at)}` : "—"],
              [t("Expires"), s.expires_at ? fmtExact(s.expires_at) : t("{n} days after approval", { n: s.expiry_days })],
              [t("On failure"), t("Stop and notify")],
            ] as [string, React.ReactNode][]
          ).map(([k, v]) => (
            <div key={k} style={{ display: "contents" }}>
              <span style={{ color: "var(--color-neutral-400)" }}>{k}</span>
              <span style={{ color: "var(--color-neutral-200)", wordBreak: "break-all" }}>{v}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }} data-testid="steps">
        <h6 className="w-h6">{t("Steps · {n}", { n: s.step_list.length })}</h6>
        {s.step_list.map((st) => (
          <div key={st.n} style={{ display: "grid", gridTemplateColumns: "32px minmax(0,1fr)", gap: 14 }} data-step={st.n}>
            <span style={{ width: 28, height: 28, borderRadius: "50%", border: "1px solid var(--color-neutral-600)", color: "var(--color-neutral-600)", fontSize: 13, display: "grid", placeItems: "center" }}>{st.n}</span>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 0 }}>
              <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
                <span style={{ fontSize: 15 }}>{st.purpose}</span>
                <span className="tag tag-neutral mono" style={{ fontSize: 11, padding: "1px 7px" }}>{st.kind}</span>
              </div>
              <pre className="mono" style={{ margin: 0, padding: "10px 12px", background: "var(--color-surface)", borderRadius: "var(--radius-md)", fontSize: 13, lineHeight: 1.55, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-neutral-100)" }}>
                {st.command}
              </pre>
              <div style={{ display: "flex", gap: 16, fontSize: 12, color: "var(--color-neutral-500)" }}>
                <span>cwd <span className="mono" style={{ color: "var(--color-neutral-300)" }}>{st.cwd}</span></span>
                <span>{t("timeout")} <span style={{ color: "var(--color-neutral-300)" }}>{fmtDur(st.timeout_s)}</span></span>
                <span>{t("expects exit")} <span style={{ color: "var(--color-neutral-300)" }}>{st.expect_exit}</span></span>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <h6 className="w-h6">{t("Recent runs")}</h6>
        {s.runs.length ? (
          s.runs.map((r) => (
            <button key={r.id} className="w-row-btn w-row-rule" onClick={() => router.push(`/plans/${encodeURIComponent(r.id)}?from=plans`)} style={{ display: "flex", gap: 12, padding: "9px 8px", fontSize: 14, alignItems: "baseline", width: "100%" }} data-run={r.id}>
              <BadgeText k={planBadgeKey(r)} style={{ minWidth: 104 }} />
              <span className="mono" style={{ flex: 1, fontSize: 12, color: "var(--color-neutral-400)" }}>{r.id}</span>
              <span style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{r.slot ? fmtExact(r.slot) : <RelTime ts={r.created_at} />}</span>
            </button>
          ))
        ) : (
          <div style={{ fontSize: 14, color: "var(--color-neutral-400)" }}>{t("No runs yet.")}</div>
        )}
      </div>

      <div className="w-actionbar" data-testid="actionbar">
        <span className="w-hint" style={{ flex: 1, fontSize: 13, color: "var(--color-neutral-400)" }} data-testid="schedule-hint">
          {offline
            ? t("Read-only while Warden is unreachable.")
            : awaiting
              ? reviewed
                ? t("All steps reviewed. Your passkey signs this schedule.")
                : t("Scroll to the last step to enable Approve.")
              : info[s.status] ?? ""}
        </span>
        {s.status !== "deleted" && (
          <button className="btn btn-secondary" disabled={offline || busy} onClick={() => setDeleting(true)}>
            <Trash size={16} /> {t("Delete")}
          </button>
        )}
        {s.status === "active" && (
          <button className="btn btn-secondary" disabled={offline || busy} onClick={() => act("pause")}>
            <Pause size={16} /> {t("Pause")}
          </button>
        )}
        {s.status === "paused" && (
          <button className="btn btn-primary" disabled={offline || busy} onClick={() => act("resume")}>
            <Play size={16} /> {t("Resume")}
          </button>
        )}
        {awaiting && (
          <button className="btn btn-primary" style={{ minWidth: 140, justifyContent: "center" }} disabled={!reviewed || offline || busy} onClick={approve} data-testid="approve-schedule">
            <Fingerprint size={16} /> {t("Approve & sign…")}
          </button>
        )}
      </div>
      {deleting && (
        <Dialog
          title={t("Delete schedule {name}?", { name: s.name })}
          onClose={() => setDeleting(false)}
          backdropClose
          actions={
            <>
              <button className="btn btn-secondary" onClick={() => setDeleting(false)}>
                {t("Cancel")}
              </button>
              <button
                className="btn w-btn-danger"
                onClick={async () => {
                  try {
                    await post(`${path}/delete`);
                    toast(t("Schedule {name} deleted", { name: s.name }), "neutral");
                    qc.invalidateQueries();
                    router.push("/schedules");
                  } catch (e) {
                    toast((e as Error).message, "bad");
                  }
                }}
              >
                {t("Delete schedule")}
              </button>
            </>
          }
        >
          <div className="dialog-body">{t("It stops running now. Its past runs stay in Plans and the audit log.")}</div>
        </Dialog>
      )}
    </section>
  );
}
