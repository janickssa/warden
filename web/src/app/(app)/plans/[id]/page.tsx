"use client";
// Plan detail (spec 5): what Claude asked for, what the reviewers think, every command in full, then the
// decision. Approve unlocks only after scrolling to the last step, and needs the passkey when Warden says so.
import { ArrowLeft, Check, Fingerprint, GitDiff, ListNumbers, PaperPlaneTilt, PencilSimple, SealCheck, Stethoscope, StopCircle, Timer, Warning, X } from "@phosphor-icons/react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { anyDialogOpen, Dialog } from "@/components/dialog";
import { isCancel, usePasskey } from "@/components/passkey";
import { ApprovalSummary, DiagnosisCard, DiffView, Steps, Verdicts } from "@/components/plan-parts";
import { BACK, KillDialog, planOrigin, useMain } from "@/components/shell";
import { Badge, Countdown, ErrorBox, planBadgeKey, RelTime, Seg, Skeleton, useNow } from "@/components/ui";
import { api, ApiError, post } from "@/lib/api";
import { fmtDur, fmtTime } from "@/lib/format";
import { useT } from "@/lib/i18n";
import { useLive } from "@/lib/live";
import { agentWarn, shortHash } from "@/lib/plan";
import { useOffline, usePhone, usePlan } from "@/lib/queries";
import { useToast } from "@/lib/toast";
import type { ApproveOptions, OutputView, PasskeyView, PlanDetail } from "@/lib/types";

export default function PlanPage() {
  const { id } = useParams<{ id: string }>();
  const planId = decodeURIComponent(id);
  const plan = usePlan(planId);
  const t = useT();
  if (plan.error && !plan.data) {
    return (
      <section className="w-page" style={{ maxWidth: 1040 }}>
        <ErrorBox error={plan.error} />
      </section>
    );
  }
  if (!plan.data) {
    return (
      <section className="w-page" style={{ maxWidth: 1040 }} aria-label={t("Loading")}>
        <Skeleton height={80} />
      </section>
    );
  }
  return <Plan p={plan.data} />;
}

function useOutput(p: PlanDetail): Record<number, string> {
  const live = useLive();
  const qc = useQueryClient();
  const hasRun = !!p.started_at || p.step_list.some((s) => s.status);
  const out = useQuery({ queryKey: ["output", p.id], queryFn: () => api<OutputView>(`/plans/${encodeURIComponent(p.id)}/output`), enabled: hasRun });
  const [extra, setExtra] = useState<{ n: number; seq: number; data: string }[]>([]);
  useEffect(() => {
    if (p.status !== "running" && p.status !== "approved") return;
    return live.watch(p.id, (o) => setExtra((x) => [...x, o]));
  }, [live, p.id, p.status]);
  useEffect(() => {
    if (p.status !== "running") qc.invalidateQueries({ queryKey: ["output", p.id] });
  }, [p.status, p.id, qc]);
  const seen = new Set<string>();
  const by: Record<number, string> = {};
  for (const c of [...(out.data?.chunks ?? []), ...extra]) {
    const k = `${c.n}:${c.seq}`;
    if (seen.has(k)) continue;
    seen.add(k);
    by[c.n] = (by[c.n] ?? "") + c.data;
  }
  return by;
}

function Plan({ p }: { p: PlanDetail }) {
  const t = useT();
  const toast = useToast();
  const router = useRouter();
  const qc = useQueryClient();
  const params = useSearchParams();
  const passkey = usePasskey();
  const offline = useOffline();
  const phone = usePhone();
  const main = useMain();
  const now = useNow();
  const output = useOutput(p);
  const passkeys = useQuery({ queryKey: ["passkeys"], queryFn: () => api<PasskeyView[]>("/passkeys"), enabled: !!p.approval?.passkey });

  const origin = planOrigin(params.get("from"), p.status);
  const [backHref, backLabel] = BACK[origin] ?? BACK.plans!;
  const [view, setView] = useState<"steps" | "diff">("steps");
  const [editing, setEditing] = useState(false);
  const [drafts, setDrafts] = useState<Record<number, string>>({});
  const [reviewedHash, setReviewedHash] = useState<string | null>(null);
  const [dialog, setDialog] = useState<null | "reject" | "diagnose" | "kill">(null);
  const [busy, setBusy] = useState(false);
  const mine = useRef(false);
  const lastStatus = useRef(p.status);

  const awaiting = p.status === "awaiting_approval";
  const expired = awaiting && new Date(p.expires_at).getTime() <= now;
  const live = awaiting && !expired;
  const reviewed = reviewedHash === p.hash;
  const needsPasskey = p.passkey_reasons.length > 0;
  const refresh = useCallback(() => qc.invalidateQueries(), [qc]);

  // README 17.3: a plan decided on another device or channel updates here and says so.
  useEffect(() => {
    const was = lastStatus.current;
    lastStatus.current = p.status;
    if (was === p.status) return;
    if (mine.current) {
      mine.current = false;
      return;
    }
    if (was === "awaiting_approval" && p.approval) toast(t("Approved on {by} {time}", { by: p.approval.by, time: fmtTime(p.approval.at) }), "neutral");
    else if (was === "awaiting_approval" && p.status === "rejected") toast(t("Rejected elsewhere · {id}", { id: p.id }), "neutral");
    else if (was === "reviewing" && p.status === "awaiting_approval") toast(t("Re-reviewed · policy and gatekeepers checked your edits"));
    else if (was === "running" && p.status === "succeeded") toast(t("Plan succeeded · {goal}", { goal: p.goal }));
    else if (was === "running" && p.status === "failed") toast(t("Failed at step {n} · {target}. Remaining steps skipped.", { n: p.failed_at ?? "?", target: p.target }), "bad");
    else if (p.status === "invalidated") toast(t("{id} invalidated by policy v{v}", { id: p.id, v: p.invalidated_by ?? "?" }), "bad");
    else if ((was === "held" || p.held_reason == null) && was !== "running" && p.status === "running") toast(t("{target} is current · {id} released to run", { target: p.target, id: p.id }));
  }, [p, t, toast]);

  // Scroll gate (spec 5.8): Approve unlocks once the last step has been on screen, on the Steps view.
  const check = useCallback(() => {
    const m = main.current;
    if (!m || !live || reviewed || editing || view !== "steps") return;
    if (m.scrollTop + m.clientHeight >= m.scrollHeight - 24) setReviewedHash(p.hash);
  }, [main, live, reviewed, editing, view, p.hash]);
  useLayoutEffect(() => {
    check();
  });
  useEffect(() => {
    const m = main.current;
    m?.addEventListener("scroll", check, { passive: true });
    window.addEventListener("resize", check);
    return () => {
      m?.removeEventListener("scroll", check);
      window.removeEventListener("resize", check);
    };
  }, [main, check]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || anyDialogOpen() || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === "r" && live && !offline && !editing) {
        e.preventDefault();
        setDialog("reject");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [live, offline, editing]);

  const approve = async () => {
    setBusy(true);
    mine.current = true;
    const path = `/plans/${encodeURIComponent(p.id)}`;
    try {
      const o = await post<ApproveOptions>(`${path}/approval/options`);
      let done: PlanDetail;
      if (o.needs_passkey) {
        const high = p.risk === "high";
        done = await passkey({
          title: high ? t("■ High-risk plan · confirm with passkey") : t("Sign this approval with your passkey"),
          body: p.e2e
            ? t("Your passkey signs the hash of {id}. {target}’s agent checks your signature, not just Warden’s, before every step. The plan can’t change afterwards.", { id: p.id, target: p.target })
            : t("Approving {id} on {target} needs a fresh passkey check. The approved plan is hashed and can’t change afterwards.", { id: p.id, target: p.target }),
          options: async () => {
            const fresh = await post<ApproveOptions>(`${path}/approval/options`);
            return { challenge_id: fresh.challenge_id!, options: fresh.options! };
          },
          submit: (signed) => post<PlanDetail>(`${path}/approve`, { hash: p.hash, ...signed }),
        });
      } else {
        done = await post<PlanDetail>(`${path}/approve`, { hash: p.hash });
      }
      qc.setQueryData(["plan", p.id], done);
      lastStatus.current = done.status;
      if (done.status === "held" || done.held_reason) toast(t("Approved · held until {target} can run it", { target: p.target }), "neutral");
      else toast(t("Approved {time} · {hash}", { time: fmtTime(done.approval?.at ?? new Date()), hash: shortHash(done.approval?.hash ?? p.hash) }));
      refresh();
    } catch (e) {
      mine.current = false;
      if (!isCancel(e)) toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
      refresh();
    } finally {
      setBusy(false);
    }
  };

  const submitEdits = async () => {
    const edits = p.step_list.filter((s) => drafts[s.n] !== undefined && drafts[s.n] !== s.command).map((s) => ({ n: s.n, command: drafts[s.n]! }));
    if (!edits.length) {
      setEditing(false);
      return;
    }
    setBusy(true);
    mine.current = true;
    try {
      const d = await post<PlanDetail>(`/plans/${encodeURIComponent(p.id)}/edits`, { edits });
      qc.setQueryData(["plan", p.id], d);
      lastStatus.current = d.status;
      setEditing(false);
      setDrafts({});
      setReviewedHash(null);
      refresh();
    } catch (e) {
      mine.current = false;
      toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
    } finally {
      setBusy(false);
    }
  };

  const running = p.status === "running";
  const done = p.step_list.filter((s) => s.status === "succeeded").length;
  const current = p.step_list.find((s) => s.status === "running")?.n ?? Math.min(p.step_list.length, done + 1);
  const elapsed = p.started_at ? (now - new Date(p.started_at).getTime()) / 1000 : null;
  const progress = running
    ? t("Running step {n} of {total}", { n: current, total: p.step_list.length }) + (elapsed != null ? ` · ${t("{d} elapsed", { d: fmtDur(elapsed) })}` : "")
    : p.status === "succeeded"
      ? t("{n} of {total} succeeded", { n: done, total: p.step_list.length })
      : null;
  const warn = ["awaiting_approval", "approved", "reviewing", "held"].includes(p.status) ? agentWarn(p.target, p.agent, t) : null;
  const passkeyName = passkeys.data?.find((k) => k.credential_id === p.approval?.passkey)?.name;

  return (
    <section className={`w-page has-actionbar`} style={{ maxWidth: 1040, paddingTop: 20, paddingBottom: 0, gap: "var(--space-8)" }}>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        <Link href={backHref} className="btn btn-ghost" style={{ fontSize: 13, alignSelf: "flex-start" }} data-testid="back">
          <ArrowLeft size={14} /> {t(backLabel)}
        </Link>
        <h1 style={{ fontSize: 30, margin: 0, textWrap: "pretty" }}>{p.goal}</h1>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", fontSize: 13, color: "var(--color-neutral-400)" }}>
          <Badge k={expired ? "expired" : planBadgeKey(p)} />
          {p.risk && <Badge k={p.risk} />}
          <span style={{ color: "var(--color-neutral-200)" }}>{p.target}</span> · <span className="mono" style={{ fontSize: 12 }}>{p.id}</span> · <span>{p.requested_by}</span> ·{" "}
          <span>
            {t("proposed")} <RelTime ts={p.created_at} />
          </span>
          {live && (
            <span style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 4, fontSize: 13 }}>
              <Timer size={14} />
              <Countdown until={p.expires_at} showClock />
            </span>
          )}
        </div>
        {p.revises && (
          <div style={{ fontSize: 13, color: "var(--color-accent-300)", display: "flex", alignItems: "center", gap: 4, flexWrap: "wrap" }}>
            <GitDiff size={14} /> {t("Revision of")} <span className="mono">#{p.revises}</span>
            {p.previous?.failed_at != null && `, ${t("which failed at step {n}", { n: p.previous.failed_at })}`}
            {p.changed_steps != null && ` · ${p.changed_steps === 1 ? t("1 changed step") : t("{n} changed steps", { n: p.changed_steps })}`}
          </div>
        )}
        {warn && (
          <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 12px", borderRadius: "var(--radius-md)", background: `color-mix(in srgb, var(--color-${warn.colour}) 12%, transparent)`, border: `1px solid color-mix(in srgb, var(--color-${warn.colour}) 35%, transparent)`, fontSize: 14 }} data-testid="agent-warning">
            <Warning size={17} color={`var(--color-${warn.colour})`} style={{ flex: "none" }} />
            <span>{warn.text}</span>
          </div>
        )}
        {p.approval?.passkey && (
          <div style={{ fontSize: 13, color: "var(--color-neutral-300)", display: "flex", alignItems: "center", gap: 6 }}>
            <SealCheck size={15} color="var(--color-ok)" />
            {t("Approval signed by your passkey “{name}” at {time} · {target}’s agent checks it before every step", { name: passkeyName ?? "…", time: fmtTime(p.approval.at), target: p.target })}
          </div>
        )}
      </div>

      {(p.human_note || p.diagnoses.length > 0) && <DiagnosisCard p={p} />}
      <Verdicts p={p} />
      {p.approval && <ApprovalSummary p={p} passkeyName={passkeyName} />}
      {p.revises && p.previous && (
        <Seg
          name="plan-view"
          value={view}
          onChange={setView}
          options={[
            { key: "steps", label: <><ListNumbers size={15} /> {t("Steps")}</> },
            { key: "diff", label: <><GitDiff size={15} /> {t("Diff vs. previous")}</> },
          ]}
        />
      )}
      {view === "diff" ? <DiffView p={p} /> : <Steps p={p} output={output} editing={editing} drafts={drafts} setDraft={(n, v) => setDrafts((d) => ({ ...d, [n]: v }))} progress={progress} />}

      <div className="w-actionbar" data-testid="actionbar">
        {live && !editing && (
          <>
            <span className="w-hint" style={{ flex: 1, fontSize: 13, color: "var(--color-neutral-400)" }}>
              {offline
                ? t("Read-only while Warden is unreachable.")
                : !reviewed
                  ? t("Scroll to the last step to enable Approve.")
                  : p.e2e && needsPasskey
                    ? t("All steps reviewed. Your passkey signs the approval.")
                    : p.risk === "high" && needsPasskey
                      ? t("High risk: approval needs a passkey confirmation.")
                      : needsPasskey
                        ? t("All steps reviewed. Approval needs a passkey confirmation.")
                        : t("All steps reviewed.")}
            </span>
            <button className="btn btn-secondary" disabled={offline || busy} onClick={() => setDialog("reject")}>
              <X size={16} /> {t("Reject")}
            </button>
            {!phone && (
              <button
                className="btn btn-secondary"
                disabled={offline || busy}
                onClick={() => {
                  setDrafts({});
                  setEditing(true);
                }}
              >
                <PencilSimple size={16} /> {t("Approve with edits")}
              </button>
            )}
            <button className="btn btn-primary" style={{ minWidth: 140, justifyContent: "center" }} disabled={!reviewed || offline || busy} onClick={approve} data-testid="approve">
              {needsPasskey ? (
                <>
                  <Fingerprint size={16} /> {t("Approve & sign…")}
                </>
              ) : (
                <>
                  <Check size={16} /> {t("Approve")}
                </>
              )}
            </button>
          </>
        )}
        {live && editing && (
          <>
            <span className="w-hint" style={{ flex: 1, fontSize: 13, color: "var(--color-neutral-400)" }}>
              {t("Edit the commands you want to change. Nothing runs until you approve the re-reviewed plan.")}
            </span>
            <button
              className="btn btn-secondary"
              disabled={busy}
              onClick={() => {
                setEditing(false);
                setDrafts({});
              }}
            >
              {t("Cancel")}
            </button>
            <button className="btn btn-primary" disabled={busy || offline} onClick={submitEdits}>
              <PaperPlaneTilt size={16} /> {t("Submit edits for review")}
            </button>
          </>
        )}
        {!live && <Info p={p} expired={expired} progress={progress} offline={offline} open={setDialog} />}
      </div>

      {dialog === "reject" && (
        <RejectDialog
          p={p}
          onClose={() => setDialog(null)}
          onDone={() => {
            mine.current = true;
            toast(t("Plan rejected · Claude has been told"), "neutral");
            refresh();
            router.push("/approvals");
          }}
        />
      )}
      {dialog === "diagnose" && <DiagnoseDialog p={p} onClose={() => setDialog(null)} />}
      {dialog === "kill" && <KillDialog planId={p.id} onClose={() => setDialog(null)} />}
    </section>
  );
}

function Info({ p, expired, progress, offline, open }: { p: PlanDetail; expired: boolean; progress: string | null; offline: boolean; open: (d: "diagnose" | "kill") => void }) {
  const t = useT();
  const router = useRouter();
  let text = "";
  let colour = "var(--color-neutral-300)";
  const at = p.approval ? fmtTime(p.approval.at) : "";
  const reason = (p.fail_reason ?? "").toLowerCase();
  if (expired || p.status === "expired") text = t("Expired at {time}. Ask Claude to propose again.", { time: fmtTime(p.expires_at) });
  else if (p.status === "reviewing") (text = t("◌ Re-reviewing your edits · policy, then gatekeepers")), (colour = "var(--color-accent-300)");
  else if (p.status === "held" || (p.status === "approved" && p.held_reason)) {
    const why = p.held_reason === "lockdown" ? t("lockdown is active") : t("{target}’s agent can’t run it yet (needs to be online on policy v{v})", { target: p.target, v: p.agent?.latest_version ?? "?" });
    text = t("⏸ Approved {time} · held: {why}. It runs as soon as it can.", { time: at, why });
    colour = "var(--color-warn)";
  } else if (p.status === "approved") (text = t("✓ Approved {time} · waiting for Claude to call execute_plan", { time: at })), (colour = "var(--color-accent-300)");
  else if (p.status === "running") (text = progress ?? ""), (colour = "var(--color-accent-300)");
  else if (p.status === "succeeded") {
    const secs = p.started_at && p.ended_at ? (new Date(p.ended_at).getTime() - new Date(p.started_at).getTime()) / 1000 : null;
    text = secs != null ? t("✓ Succeeded in {d}", { d: fmtDur(secs) }) : t("✓ Succeeded");
    colour = "var(--color-ok)";
  } else if (p.status === "failed") {
    colour = "var(--color-danger)";
    if (reason.includes("policy_violation") || reason.includes("refused"))
      text = t("✕ {target}’s agent refused step {n} · policy_violation. Claude must propose a revision.", { target: p.target, n: p.failed_at ?? "?" });
    else if (reason.includes("agent_disconnected"))
      text = t("✕ Failed at step {n} · agent_disconnected. The agent killed the step and aborted the rest.", { n: p.failed_at ?? "?" });
    else text = t("✕ Failed at step {n}. Remaining steps skipped. Claude must propose a revision with revises: {id}.", { n: p.failed_at ?? "?", id: p.id });
  } else if (p.status === "invalidated") {
    colour = "var(--color-warn)";
    text = p.invalid_reason ? t("⊘ {reason}. Claude must propose a new plan.", { reason: p.invalid_reason.replace(/\.$/, "") }) : t("⊘ Invalidated by a newer policy. Claude must propose a new plan.");
  } else if (p.status === "cancelled") text = t("— Cancelled by kill switch. Claude must propose a new plan.");
  else if (p.status === "rejected") text = p.reject_reason ? t("Rejected · “{reason}”", { reason: p.reject_reason }) : t("Rejected");

  const revision = p.revisions[0];
  const expiredButtons = expired && (
    <>
      <button className="btn btn-secondary" disabled>
        <X size={16} /> {t("Reject")}
      </button>
      <button className="btn btn-primary" disabled style={{ minWidth: 140, justifyContent: "center" }}>
        <Check size={16} /> {t("Approve")}
      </button>
    </>
  );
  return (
    <>
      <span className="w-hint" style={{ flex: 1, fontSize: 14, color: colour }} data-testid="plan-info">
        {text}
      </span>
      {expiredButtons}
      {p.status === "failed" && !revision && !p.human_note && !p.diagnoses.length && (
        <button className="btn btn-primary" disabled={offline} onClick={() => open("diagnose")}>
          <Stethoscope size={16} /> {t("Diagnose & propose fix…")}
        </button>
      )}
      {revision && !p.diagnoses.length && (
        <button className="btn btn-secondary" onClick={() => router.push(`/plans/${encodeURIComponent(revision)}?from=plans`)}>
          <GitDiff size={16} /> {t("Open revision {id}", { id: revision })}
        </button>
      )}
      {p.status === "running" && (
        <button className="btn w-btn-danger" disabled={offline} onClick={() => open("kill")}>
          <StopCircle size={16} weight="fill" /> {t("Kill switch")}
        </button>
      )}
    </>
  );
}

function RejectDialog({ p, onClose, onDone }: { p: PlanDetail; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try {
      await post(`/plans/${encodeURIComponent(p.id)}/reject`, { reason: reason.trim() || null });
      onDone();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={t("Reject plan")}
      onClose={onClose}
      backdropClose
      busy={busy}
      testId="reject-dialog"
      actions={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
            {t("Cancel")}
          </button>
          <button className="btn btn-primary" onClick={go} disabled={busy}>
            {t("Reject plan")}
          </button>
        </>
      }
    >
      <div className="dialog-body">{t("Claude will be told the plan was rejected, with your reason if you give one.")}</div>
      <div className="field">
        <label htmlFor="reject-reason">{t("Reason (optional)")}</label>
        <textarea id="reject-reason" className="input" maxLength={500} placeholder={t("e.g. Use port 3001 instead")} value={reason} onChange={(e) => setReason(e.target.value)} />
      </div>
    </Dialog>
  );
}

function DiagnoseDialog({ p, onClose }: { p: PlanDetail; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try {
      const d = await post<PlanDetail>(`/plans/${encodeURIComponent(p.id)}/diagnose`, { note: note.trim() });
      qc.setQueryData(["plan", p.id], d);
      toast(t("Sent to {client} · it sees your note in get_plan", { client: p.requested_by }), "neutral");
      onClose();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={t("Diagnose and propose a fix")}
      onClose={onClose}
      backdropClose
      busy={busy}
      width={520}
      actions={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
            {t("Cancel")}
          </button>
          <button className="btn btn-primary" onClick={go} disabled={busy}>
            <PaperPlaneTilt size={16} /> {t("Send to {client}", { client: p.requested_by })}
          </button>
        </>
      }
    >
      <div className="dialog-body">
        {t("{client} gets the failed step, its output and your note. It can look around with read-only commands (no approval, all logged), then proposes a revision of {id}. Nothing changes until you approve that.", {
          client: p.requested_by,
          id: p.id,
        })}
      </div>
      <div className="field">
        <label htmlFor="diag-note">{t("Note for Claude (optional)")}</label>
        <textarea id="diag-note" className="input" maxLength={4000} placeholder={t("e.g. Don’t stop dev-legacy-web, it’s in use")} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
    </Dialog>
  );
}
