"use client";
// Plan detail sections (spec 5.2–5.6 and README 17.3 "After approval"): diagnosis, verdicts, steps with
// their output, the diff against the failed plan, and the approval summary.
import { ArrowRight, ChatCircleText, Eye, PencilSimple } from "@phosphor-icons/react";
import Link from "next/link";
import { fmtDur, fmtTime } from "@/lib/format";
import { useT } from "@/lib/i18n";
import { shortHash } from "@/lib/plan";
import type { PlanDetail, StepView } from "@/lib/types";
import { Terminal } from "./terminal";
import { badgeOf, BadgeText, colourVar } from "./ui";

const box = (c: string, pct: number) => `color-mix(in srgb, var(--color-${c}) ${pct}%, transparent)`;

export function DiagnosisCard({ p }: { p: PlanDetail }) {
  const t = useT();
  const revision = p.revisions[0];
  return (
    <div className="card elev-sm" style={{ padding: "14px 16px", gap: 12 }} data-testid="diagnosis">
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "baseline" }}>
        <h6 className="w-h6">{t("Diagnosis")}</h6>
        {revision ? (
          <span style={{ fontSize: 13, color: "var(--color-ok)" }}>{t("✓ Revision proposed")}</span>
        ) : (
          <span style={{ fontSize: 13, color: "var(--color-accent-300)" }}>{t("◌ Investigating")}</span>
        )}
        <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--color-neutral-500)" }}>{t("Read-only commands run without approval and are logged")}</span>
      </div>
      {p.human_note && (
        <div style={{ fontSize: 13, color: "var(--color-neutral-300)" }}>
          <span style={{ color: "var(--color-neutral-500)" }}>{t("Your note:")}</span> “{p.human_note}”
        </div>
      )}
      {p.diagnoses.map((d) => (
        <div key={d.id} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {d.evidence.map((e) => (
            <div key={e.audit_id} style={{ borderRadius: "var(--radius-md)", border: "1px solid var(--color-divider)", overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: "var(--color-bg)", fontSize: 12, color: "var(--color-neutral-400)", flexWrap: "wrap" }}>
                <Eye size={13} /> read_only · {d.by}
                <span className="mono" style={{ fontSize: 12.5, color: "var(--color-neutral-100)" }}>{e.command}</span>
                <span style={{ marginLeft: "auto", color: e.exit_code === 0 ? "var(--color-ok)" : "var(--color-danger)" }}>
                  {e.exit_code === 0 ? "✓ exit 0" : `✕ exit ${e.exit_code ?? "?"}`}
                </span>
              </div>
              <div className="mono" style={{ padding: "8px 12px", fontSize: 12.5, lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-neutral-300)", maxHeight: 200, overflow: "auto" }}>
                {e.output}
              </div>
            </div>
          ))}
          <div style={{ display: "flex", gap: 10, padding: "10px 12px", borderRadius: "var(--radius-md)", background: "var(--color-accent-900)", border: "1px solid var(--color-accent-800)" }}>
            <ChatCircleText size={18} color="var(--color-accent-300)" style={{ marginTop: 2, flex: "none" }} />
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              <span style={{ fontSize: 12, color: "var(--color-accent-300)" }}>{d.by}</span>
              <span style={{ fontSize: 14, lineHeight: 1.5, color: "var(--color-neutral-100)", whiteSpace: "pre-wrap" }}>{d.note}</span>
            </div>
          </div>
        </div>
      ))}
      {!p.diagnoses.length && !revision && (
        <div style={{ fontSize: 13, color: "var(--color-accent-300)" }}>{t("◌ Sent to Claude · it reads your note the next time it looks at this plan…")}</div>
      )}
      {revision && (
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", fontSize: 13, color: "var(--color-neutral-300)" }}>
          <span style={{ flex: 1 }}>
            {t("Proposed")} <span className="mono">{revision}</span>
          </span>
          <Link className="btn btn-primary" style={{ fontSize: 13 }} href={`/plans/${encodeURIComponent(revision)}?from=plans`}>
            {t("Review revision")} <ArrowRight size={14} />
          </Link>
        </div>
      )}
    </div>
  );
}

export function Verdicts({ p, timeout }: { p: PlanDetail; timeout?: number }) {
  const t = useT();
  const [finalLabel, finalC] = badgeOf(p.final_verdict);
  return (
    <div className="card elev-sm" style={{ padding: 0, gap: 0 }} data-testid="verdicts">
      <div style={{ display: "flex", gap: 10, padding: "12px 16px", alignItems: "baseline", flexWrap: "wrap" }}>
        <h6 className="w-h6">{t("Verdicts")}</h6>
        {p.reviewers_disagree && <span style={{ fontSize: 12, color: "var(--color-warn)" }}>{t("▲ Reviewers disagree")}</span>}
        <span style={{ marginLeft: "auto", fontSize: 13, color: "var(--color-neutral-400)" }}>
          {t("Final, strictest wins:")} <span style={{ color: colourVar(finalC) }}>{t(finalLabel)}</span>
        </span>
      </div>
      <div className="w-grid-verdict">
        <span>{t("Policy")}</span>
        <span style={{ fontSize: 13, color: p.policy_ok ? "var(--color-ok)" : "var(--color-danger)" }}>{p.policy_ok ? t("✓ Passed") : t("✕ Denied")}</span>
        <span style={{ color: "var(--color-neutral-300)" }}>
          {p.policy_ok
            ? t("Passed · every command matched the allowlist")
            : p.violations.map((v) => (v.step ? t("step {n}: {msg}", { n: v.step, msg: v.message }) : v.message)).join(" · ")}
        </span>
      </div>
      {p.reviewers.map((r) => {
        const highlight = r.unavailable || (p.reviewers_disagree && r.verdict !== "allow");
        return (
          <div key={r.name} className="w-grid-verdict" style={{ background: highlight ? box("warn", 8) : undefined }} data-reviewer={r.name}>
            <span>
              {r.name}
              <span className="mono" style={{ display: "block", fontSize: 11, color: "var(--color-neutral-500)" }}>{r.model}</span>
            </span>
            {r.unavailable ? (
              <span style={{ fontSize: 13, color: "var(--color-warn)" }}>{t("○ Unavailable · counted as escalate")}</span>
            ) : (
              <BadgeText k={r.verdict} size={13} />
            )}
            <span style={{ color: "var(--color-neutral-200)" }}>
              {r.unavailable && timeout ? t("No answer within {s} s. Counted as escalate, so this plan can’t be finalised as allow.", { s: timeout }) : r.summary}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function marker(s: StepView, active: boolean): [string, string] {
  if (s.status === "succeeded") return ["✓", colourVar("ok")];
  if (s.status === "failed" || s.status === "refused") return ["✕", colourVar("danger")];
  if (s.status === "skipped" || s.status === "cancelled") return ["—", colourVar("neutral")];
  if (s.status === "running" || active) return [String(s.n), "var(--color-accent)"];
  return [String(s.n), "var(--color-neutral-600)"];
}

export function Steps({
  p,
  output,
  editing,
  drafts,
  setDraft,
  progress,
}: {
  p: PlanDetail;
  output: Record<number, string>;
  editing: boolean;
  drafts: Record<number, string>;
  setDraft: (n: number, v: string) => void;
  progress: string | null;
}) {
  const t = useT();
  const notes = new Map<number, { by: string; note: string }[]>();
  for (const r of p.reviewers) for (const [n, note] of Object.entries(r.notes ?? {})) if (note) notes.set(Number(n), [...(notes.get(Number(n)) ?? []), { by: r.name, note }]);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }} data-testid="steps">
      <div style={{ display: "flex", gap: 12, alignItems: "baseline", flexWrap: "wrap" }}>
        <h6 className="w-h6">{t("Steps · {n}", { n: p.step_list.length })}</h6>
        {progress && <span style={{ fontSize: 13, color: "var(--color-accent-300)" }}>{progress}</span>}
      </div>
      {editing && (
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", padding: "12px 14px", borderRadius: "var(--radius-md)", border: "1px solid var(--color-accent-700)", background: "var(--color-accent-900)", fontSize: 14, color: "var(--color-accent-200)" }}>
          <PencilSimple size={16} style={{ marginTop: 3, flex: "none" }} />
          <span>{t("You’re editing commands. Submitting creates a new plan hash; policy and every gatekeeper review it again before you can approve.")}</span>
        </div>
      )}
      {p.step_list.map((s) => {
        const active = s.status === "running";
        const [mark, ring] = marker(s, active);
        const changed = editing && drafts[s.n] !== undefined && drafts[s.n] !== s.command;
        const border = changed ? "var(--color-accent)" : active ? "var(--color-accent-700)" : "transparent";
        const out = output[s.n];
        return (
          <div key={s.n} style={{ display: "grid", gridTemplateColumns: "32px minmax(0,1fr)", gap: 14 }} data-step={s.n}>
            <span style={{ width: 28, height: 28, borderRadius: "50%", border: `1px solid ${ring}`, color: ring, fontSize: 13, display: "grid", placeItems: "center" }}>{mark}</span>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, minWidth: 0, opacity: s.status === "skipped" ? 0.5 : 1 }}>
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center", minHeight: 28 }}>
                <span style={{ fontSize: 15 }}>{s.purpose}</span>
                <span className="tag tag-neutral mono" style={{ fontSize: 11, padding: "1px 7px" }}>{s.kind}</span>
                {(s.edited || changed) && <span className="tag tag-accent" style={{ padding: "1px 7px" }}>{t("Edited by you")}</span>}
                {s.status && s.status !== "pending" && <BadgeText k={s.status} style={{ marginLeft: "auto" }} suffix={s.duration_s != null ? ` · ${fmtDur(s.duration_s)}` : ""} />}
              </div>
              {editing ? (
                <textarea
                  className="input mono"
                  rows={2}
                  aria-label={t("Command for step {n}", { n: s.n })}
                  value={drafts[s.n] ?? s.command}
                  onChange={(e) => setDraft(s.n, e.target.value)}
                  style={{ fontSize: 13, minHeight: 44, border: `1px solid ${border}` }}
                />
              ) : (
                <pre className="mono" style={{ margin: 0, padding: "10px 12px", background: "var(--color-surface)", border: `1px solid ${border}`, borderRadius: "var(--radius-md)", fontSize: 13, lineHeight: 1.55, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-neutral-100)" }}>
                  {s.command}
                </pre>
              )}
              <div style={{ display: "flex", gap: 16, fontSize: 12, color: "var(--color-neutral-500)", flexWrap: "wrap" }}>
                <span>
                  cwd <span className="mono" style={{ color: "var(--color-neutral-300)" }}>{s.cwd}</span>
                </span>
                <span>
                  {t("timeout")} <span style={{ color: "var(--color-neutral-300)" }}>{fmtDur(s.timeout_s)}</span>
                </span>
                <span>
                  {t("expects exit")} <span style={{ color: "var(--color-neutral-300)" }}>{s.expect_exit}</span>
                </span>
                {s.exit_code != null && s.exit_code !== s.expect_exit && (
                  <span style={{ color: "var(--color-danger)" }}>
                    {t("exited")} {s.exit_code}
                  </span>
                )}
              </div>
              {s.reason && s.status !== "succeeded" && <div style={{ fontSize: 13, color: "var(--color-danger)" }}>{s.reason}</div>}
              {(notes.get(s.n) ?? []).map((n) => (
                <div key={n.by} style={{ display: "flex", gap: 8, padding: "8px 12px", borderRadius: "var(--radius-md)", background: box("warn", 10), fontSize: 13, color: "var(--color-neutral-200)" }}>
                  <span style={{ color: "var(--color-warn)", whiteSpace: "nowrap" }}>▲ {n.by}</span>
                  <span>{n.note}</span>
                </div>
              ))}
              {out && <Terminal text={out} live={active} truncated={s.output_truncated} />}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function DiffView({ p }: { p: PlanDetail }) {
  const t = useT();
  const prev = p.previous;
  const errLines = (prev?.error_output ?? "").trimEnd().split("\n").slice(-4).join("\n");
  const cell: React.CSSProperties = { padding: "10px 12px", borderRadius: "var(--radius-md)", display: "flex", flexDirection: "column", gap: 6, minHeight: 64 };
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "var(--space-6)" }} data-testid="diff">
      {prev?.failed_at != null && (
        <div style={{ borderRadius: "var(--radius-md)", border: `1px solid ${box("danger", 35)}`, overflow: "hidden" }}>
          <div style={{ padding: "8px 12px", fontSize: 13, background: box("danger", 10) }}>
            <span style={{ color: "var(--color-danger)" }}>
              {t("✕ Failed at step {n}", { n: prev.failed_at })}
              {prev.fail_reason ? ` · ${prev.fail_reason}` : ""}
            </span>{" "}
            · <span className="mono">#{prev.id}</span>
          </div>
          {errLines && (
            <div className="mono" style={{ padding: "10px 12px", fontSize: 12.5, lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-neutral-200)" }}>
              {errLines}
            </div>
          )}
        </div>
      )}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: "8px 12px" }}>
        <h6 className="w-h6">{t("Previous · #{id}", { id: prev?.id ?? p.revises ?? "" })}</h6>
        <h6 className="w-h6">{t("This revision · #{id}", { id: p.id })}</h6>
        {p.diff.map((r, i) => {
          const oldFailed = r.old_status === "failed" || r.old_status === "refused";
          return (
            <div key={i} style={{ display: "contents" }}>
              <div
                style={{
                  ...cell,
                  background: r.op === "removed" ? box("danger", 8) : r.old_command != null ? "var(--color-surface)" : "transparent",
                  border: `1px solid ${r.old_command != null ? (oldFailed ? box("danger", 45) : "transparent") : "var(--color-divider)"}`,
                }}
              >
                {r.old_command != null && (
                  <>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "var(--color-neutral-500)" }}>
                      <span>{t("Step {n}", { n: r.old_n ?? "" })}</span>
                      {r.old_status && <BadgeText k={r.old_status} />}
                    </div>
                    <span className="mono" style={{ fontSize: 13, color: "var(--color-neutral-400)", wordBreak: "break-all" }}>{r.old_command}</span>
                  </>
                )}
              </div>
              <div
                style={{
                  ...cell,
                  background: r.op === "added" ? box("ok", 9) : r.new_command != null ? "var(--color-surface)" : "transparent",
                  border: `1px solid ${r.op === "added" ? box("ok", 40) : r.new_command != null ? "transparent" : "var(--color-divider)"}`,
                }}
              >
                {r.new_command != null ? (
                  <>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: "var(--color-neutral-500)" }}>
                      <span>{t("Step {n}", { n: r.new_n ?? "" })}</span>
                      {r.op === "added" ? <span style={{ color: "var(--color-ok)" }}>{t("+ Added")}</span> : <span>{t("Unchanged")}</span>}
                    </div>
                    <span className="mono" style={{ fontSize: 13, color: "var(--color-neutral-100)", wordBreak: "break-all" }}>{r.new_command}</span>
                  </>
                ) : r.old_status === "succeeded" ? (
                  <span style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{t("Already ran ✓ · not repeated")}</span>
                ) : (
                  <span style={{ fontSize: 12, color: "var(--color-danger)" }}>{t("Dropped in the revision")}</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function ApprovalSummary({ p, passkeyName }: { p: PlanDetail; passkeyName?: string }) {
  const t = useT();
  const a = p.approval;
  if (!a) return null;
  const rows: [string, React.ReactNode][] = [
    [t("Channel"), `${a.by} · ${fmtTime(a.at)}`],
    [t("Plan hash"), <span key="h" className="mono" title={a.hash}>{shortHash(a.hash)}</span>],
    [
      t("Approval signature"),
      a.passkey ? t("ed25519 by your passkey “{name}” · agents verify it", { name: passkeyName ?? a.passkey.slice(0, 8) }) : t("Warden approval key {key}", { key: a.key_id }),
    ],
    [t("Risk at approval"), p.risk ? <BadgeText key="r" k={p.risk} size={13} /> : "—"],
    [t("Gatekeepers"), p.reviewers.map((r) => `${r.name} ${r.unavailable ? t("unavailable") : r.verdict}`).join(" · ") || "—"],
  ];
  return (
    <div className="card elev-sm" style={{ padding: "12px 16px", gap: 8 }} data-testid="approval-summary">
      <h6 className="w-h6">{t("After approval")}</h6>
      <div style={{ display: "grid", gridTemplateColumns: "160px minmax(0,1fr)", gap: "6px 16px", fontSize: 13 }}>
        {rows.map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <span style={{ color: "var(--color-neutral-400)" }}>{k}</span>
            <span style={{ color: "var(--color-neutral-200)", wordBreak: "break-all" }}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
