"use client";
// Rule editing shared by Policy and Groups (spec 9.2, 10.4, 10.5): chip lists and numbers that show
// whether each edit tightens or loosens, the Changes box from Warden's own classifier, and publishing.
import { ArrowCounterClockwise, CheckCircle, Flask, X, XCircle } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, post } from "@/lib/api";
import { N, useT } from "@/lib/i18n";
import { useToast } from "@/lib/toast";
import type { ApproveOptions, PolicyPreview, PublishResult } from "@/lib/types";
import { isCancel, usePasskey } from "./passkey";
import { Badge, Spinner } from "./ui";

type Effect = "tighten" | "loosen";
// Notes Warden attaches to previews; registered here so they get a Danish entry.
export const NOTES = [N("Saving from the form rewrites policy.yaml; comments in it are not kept."), N("Saving from the group editor rewrites policy.yaml; comments in it are not kept.")];
const tint = (c: string, p: number) => `color-mix(in srgb, var(--color-${c}) ${p}%, transparent)`;

export function FieldRow({ label, path, hint, children, last }: { label: string; path?: string; hint?: string; children: React.ReactNode; last?: boolean }) {
  return (
    <div data-field={path} style={{ display: "flex", flexDirection: "column", gap: 8, padding: "12px 0", borderBottom: last ? "1px solid transparent" : "1px solid var(--color-divider)" }}>
      <div style={{ display: "flex", gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
        <span style={{ fontSize: 14 }}>{label}</span>
        {path && <span className="mono" style={{ fontSize: 11, color: "var(--color-neutral-500)" }}>{path}</span>}
        {hint && <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--color-neutral-500)" }}>{hint}</span>}
      </div>
      {children}
    </div>
  );
}

/** A list where adding tightens (`deny`) or removing tightens (`allow`). Removed values stay, struck out. */
export function ListField({
  value,
  saved,
  onChange,
  kind,
  disabled,
  placeholder,
  surface,
}: {
  value: string[];
  saved: string[];
  onChange: (v: string[]) => void;
  kind: "deny" | "allow";
  disabled?: boolean;
  placeholder?: string;
  surface?: boolean;
}) {
  const t = useT();
  const [draft, setDraft] = useState("");
  const shown = [...value, ...saved.filter((s) => !value.includes(s))];
  const effect = (v: string): Effect | null => {
    const added = value.includes(v) && !saved.includes(v);
    const removed = !value.includes(v) && saved.includes(v);
    if (!added && !removed) return null;
    return added === (kind === "deny") ? "tighten" : "loosen";
  };
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
      {shown.map((v) => {
        const e = effect(v);
        const removed = !value.includes(v);
        return (
          <span
            key={v}
            className="mono"
            data-chip={v}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 2,
              padding: "1px 2px 1px 8px",
              borderRadius: "var(--radius-sm)",
              fontSize: 12.5,
              background: e ? tint(e === "tighten" ? "ok" : "warn", 12) : surface ? "var(--color-surface)" : "var(--color-bg)",
              border: `1px solid ${e ? tint(e === "tighten" ? "ok" : "warn", 45) : "var(--color-divider)"}`,
              color: removed ? "var(--color-neutral-400)" : "var(--color-neutral-100)",
              textDecoration: removed ? "line-through" : undefined,
            }}
          >
            {v}
            <button
              type="button"
              disabled={disabled}
              aria-label={removed ? t("Restore {v}", { v }) : t("Remove {v}", { v })}
              title={removed ? t("Restore {v}", { v }) : t("Remove {v}", { v })}
              onClick={() => onChange(removed ? [...value, v] : value.filter((x) => x !== v))}
              style={{ width: 22, height: 22, borderRadius: 4, border: 0, background: "transparent", color: "var(--color-neutral-400)", display: "grid", placeItems: "center", cursor: "pointer" }}
            >
              {removed ? <ArrowCounterClockwise size={12} /> : <X size={12} />}
            </button>
          </span>
        );
      })}
      <input
        className="input mono"
        disabled={disabled}
        placeholder={placeholder ?? t("Add, then Enter")}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={(e) => {
          if (e.key !== "Enter") return;
          e.preventDefault();
          const v = draft.trim();
          if (v && !value.includes(v)) onChange([...value, v]);
          setDraft("");
        }}
        style={{ width: 170, minHeight: 28, padding: "3px 8px", fontSize: 12.5 }}
      />
    </div>
  );
}

/** A limit where lowering tightens. */
export function NumberField({ value, saved, onChange, unit, disabled }: { value: number; saved: number; onChange: (v: number) => void; unit: string; disabled?: boolean }) {
  const t = useT();
  const changed = value !== saved;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <input
        type="number"
        min={1}
        className="input"
        disabled={disabled}
        value={Number.isFinite(value) ? value : ""}
        onChange={(e) => onChange(e.target.value === "" ? NaN : Number(e.target.value))}
        style={{ width: 96, fontVariantNumeric: "tabular-nums", borderColor: !changed ? undefined : value < saved ? "var(--color-ok)" : "var(--color-warn)" }}
      />
      <span style={{ fontSize: 13, color: "var(--color-neutral-400)" }}>{unit}</span>
      {changed && <span style={{ fontSize: 12, color: "var(--color-neutral-500)" }}>{t("was {v}", { v: saved })}</span>}
    </div>
  );
}

export function changeLines(pv: PolicyPreview | undefined): { effect: string; text: string }[] {
  const seen = new Set<string>();
  const out: { effect: string; text: string }[] = [];
  for (const tc of pv?.targets ?? []) {
    for (const c of tc.changes) {
      const text = c.op === "add" ? `+ ${c.path}: ${c.detail}` : c.op === "remove" ? `− ${c.path}: ${c.detail}` : `${c.path}: ${c.detail}`;
      if (seen.has(text)) continue;
      seen.add(text);
      out.push({ effect: c.effect ?? "loosen", text });
    }
  }
  return out;
}

export function ChangesBox({ pv, pending, errors, hints, card }: { pv?: PolicyPreview; pending: boolean; errors?: string[]; hints: Record<string, string>; card?: boolean }) {
  const t = useT();
  const cls = pv?.cls ?? "none";
  const lines = changeLines(pv);
  const allErrors = [...(errors ?? []), ...(pv?.errors ?? [])];
  const style: React.CSSProperties = card
    ? { padding: "14px 16px", gap: 12 }
    : { display: "flex", flexDirection: "column", gap: 8, padding: "12px 14px", borderRadius: "var(--radius-md)", background: "var(--color-bg)" };
  return (
    <div className={card ? "card elev-sm" : undefined} style={style} data-testid="changes">
      <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
        <h6 className="w-h6">{t("Changes")}</h6>
        {pending ? <Spinner size={14} /> : <Badge k={cls === "initial" ? "loosen" : cls} />}
        <span style={{ fontSize: 13, color: "var(--color-neutral-400)" }}>{t(hints[cls === "initial" ? "loosen" : cls] ?? hints.none ?? "")}</span>
      </div>
      {lines.map((l) => (
        <div key={l.text} className="mono" style={{ display: "flex", gap: 12, fontSize: 12.5 }}>
          <span style={{ width: 80, flex: "none", color: l.effect === "tighten" ? "var(--color-ok)" : "var(--color-warn)" }}>{l.effect === "tighten" ? t("↓ tighten") : t("↑ loosen")}</span>
          <span style={{ color: "var(--color-neutral-100)", wordBreak: "break-all" }}>{l.text}</span>
        </div>
      ))}
      {allErrors.map((e) => (
        <div key={e} style={{ fontSize: 13, color: "var(--color-danger)" }}>
          ✕ {e}
        </div>
      ))}
      {pv && cls !== "none" && !pv.errors.length && (
        <>
          <div style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 13, color: pv.gate_failures.length ? "var(--color-danger)" : "var(--color-ok)" }}>
            {pv.gate_failures.length ? <XCircle size={16} /> : <CheckCircle size={16} />}
            {t("{ok} / {n} policy tests passed", { ok: pv.gate_cases - pv.gate_failures.length, n: pv.gate_cases })}
          </div>
          {pv.gate_failures.map((f) => (
            <div key={f} className="mono" style={{ fontSize: 12.5, color: "var(--color-danger)", paddingLeft: 24 }}>
              ✕ {f}
            </div>
          ))}
        </>
      )}
      {!pv && !pending && cls === "none" && (
        <div style={{ display: "flex", gap: 6, alignItems: "center", fontSize: 13, color: "var(--color-neutral-300)" }}>
          <Flask size={16} /> {t("Tests run with every change")}
        </div>
      )}
      {pv?.note && cls !== "none" && <div style={{ fontSize: 12, color: "var(--color-neutral-500)" }}>{t(pv.note)}</div>}
    </div>
  );
}

/** Publish a previewed change: passkey, then published (tighten) or a pending bundle (loosen). */
export function usePublish() {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const passkey = usePasskey();
  return async (pv: PolicyPreview, next: number, texts: { title: string; body: string; published: string; pending: string }): Promise<PublishResult | null> => {
    if (!pv.preview_id) return null;
    try {
      const r = await passkey({
        title: texts.title,
        body: texts.body,
        options: async () => {
          const o = await post<ApproveOptions>(`/policy/publish/options?preview_id=${encodeURIComponent(pv.preview_id!)}`);
          return { challenge_id: o.challenge_id!, options: o.options! };
        },
        submit: (signed) => post<PublishResult>("/policy/publish", { preview_id: pv.preview_id, ...signed }),
      });
      if (r.outcome === "pending") toast(texts.pending.replace("{v}", String(r.version)), "neutral");
      else if (r.outcome === "published") toast(texts.published.replace("{v}", String(r.version)));
      else toast(t("Nothing to publish · v{v} is already live", { v: next - 1 }), "neutral");
      for (const id of r.invalidated) toast(t("{id} invalidated by policy v{v}", { id, v: r.version }), "bad");
      qc.invalidateQueries();
      return r;
    } catch (e) {
      if (!isCancel(e)) toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
      return null;
    }
  };
}
