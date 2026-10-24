"use client";
// Audit log (spec 11): every entry, hash-chained. Search, filter by kind, expand an entry to see what
// it recorded, export JSONL. Read-only: nothing here changes anything.
import { ArrowSquareOut, ArrowsInLineVertical, ArrowsOutLineVertical, BracketsCurly, CaretDown, CaretRight, Copy, DownloadSimple } from "@phosphor-icons/react";
import { keepPreviousData, useInfiniteQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { copyText, ErrorBox, Header, Page, Seg, Skeleton, useDebounced } from "@/components/ui";
import { api } from "@/lib/api";
import { fmtDate, fmtTime } from "@/lib/format";
import { N, useT } from "@/lib/i18n";
import { useToast } from "@/lib/toast";
import type { AuditEntry, AuditPage } from "@/lib/types";

const KINDS = [
  ["all", N("All")],
  ["plans", N("Plans")],
  ["decisions", N("Decisions")],
  ["output", N("Commands & output")],
  ["policy", N("Policy & agents")],
  ["settings", N("Settings & access")],
] as const;
const COLS = "14px 48px 64px 120px 128px minmax(0,1fr) 52px";

export default function Audit() {
  const t = useT();
  const [search, setSearch] = useState("");
  const [kind, setKind] = useState<string>("all");
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [all, setAll] = useState(false);
  const q = useDebounced(search.trim());
  const pages = useInfiniteQuery({
    queryKey: ["audit", q, kind],
    queryFn: ({ pageParam }) => api<AuditPage>(`/audit?q=${encodeURIComponent(q)}&kind=${kind}${pageParam ? `&before=${pageParam}` : ""}`),
    initialPageParam: 0,
    getNextPageParam: (last) => (last.entries.length >= 100 ? last.entries[last.entries.length - 1]!.seq : undefined),
    placeholderData: keepPreviousData,
  });
  const first = pages.data?.pages[0];
  const entries = pages.data?.pages.flatMap((p) => p.entries) ?? [];
  const isOpen = (seq: number) => all !== open.has(seq);
  return (
    <Page max={1040}>
      <Header
        title={t("Audit log")}
        sub={
          first ? (
            first.chain_ok ? (
              <span style={{ color: "var(--color-ok)" }} data-testid="chain">{t("✓ Hash chain verified · {n} entries", { n: first.chain_count })}</span>
            ) : (
              <span style={{ color: "var(--color-danger)" }} data-testid="chain">{t("✕ Hash chain broken at entry {seq}", { seq: first.chain_bad_seq ?? "?" })}</span>
            )
          ) : (
            " "
          )
        }
      >
        <input className="input" style={{ maxWidth: 280 }} placeholder={t("Search actor, plan, command, output…")} value={search} onChange={(e) => setSearch(e.target.value)} aria-label={t("Search")} />
        <a className="btn btn-secondary" href="/api/audit/export" download="warden-audit.jsonl">
          <DownloadSimple size={16} /> {t("Export JSONL")}
        </a>
      </Header>
      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <Seg name="audit-kind" value={kind} onChange={setKind} options={KINDS.map(([k, l]) => ({ key: k, label: t(l) }))} />
        <button
          className="btn btn-ghost"
          style={{ fontSize: 13, marginLeft: "auto" }}
          onClick={() => {
            setAll(!all);
            setOpen(new Set());
          }}
        >
          {all ? <ArrowsInLineVertical size={15} /> : <ArrowsOutLineVertical size={15} />} {all ? t("Collapse all") : t("Expand all")}
        </button>
      </div>
      <ErrorBox error={pages.error && !pages.data ? pages.error : null} />
      <div style={{ overflowX: "auto" }}>
        <div style={{ minWidth: 720 }}>
          <div className="w-head-row" style={{ gridTemplateColumns: COLS }}>
            <span />
            <span>#</span>
            <span>{t("Time")}</span>
            <span>{t("Actor")}</span>
            <span>{t("Action")}</span>
            <span>{t("Subject")}</span>
            <span>{t("Hash")}</span>
          </div>
          {pages.isPending ? (
            <div style={{ paddingTop: 8 }}>
              <Skeleton height={36} gap={8} />
            </div>
          ) : entries.length ? (
            entries.map((e) => (
              <Row
                key={e.seq}
                e={e}
                open={isOpen(e.seq)}
                toggle={() =>
                  setOpen((s) => {
                    const n = new Set(s);
                    if (n.has(e.seq)) n.delete(e.seq);
                    else n.add(e.seq);
                    return n;
                  })
                }
              />
            ))
          ) : (
            <div style={{ fontSize: 14, color: "var(--color-neutral-400)", padding: "16px 8px" }}>{t("No entries match.")}</div>
          )}
        </div>
      </div>
      {pages.hasNextPage && (
        <button className="btn btn-secondary" style={{ alignSelf: "center" }} disabled={pages.isFetchingNextPage} onClick={() => pages.fetchNextPage()}>
          {t("Load older entries")}
        </button>
      )}
    </Page>
  );
}

const isPlan = (s: string) => /^pln_[0-9A-Z]{26}/.test(s);

function Row({ e, open, toggle }: { e: AuditEntry; open: boolean; toggle: () => void }) {
  const t = useT();
  const toast = useToast();
  const router = useRouter();
  const planId = isPlan(e.subject) ? e.subject.slice(0, 30) : typeof e.detail.plan_id === "string" ? e.detail.plan_id : null;
  return (
    <div>
      <button
        className="w-row-btn w-row-rule"
        aria-expanded={open}
        onClick={toggle}
        data-audit={e.seq}
        style={{ display: "grid", gridTemplateColumns: COLS, gap: 12, padding: "9px 8px", alignItems: "baseline", width: "100%", background: open ? "color-mix(in srgb, var(--color-text) 4%, transparent)" : undefined }}
      >
        {open ? <CaretDown size={13} color="var(--color-neutral-400)" /> : <CaretRight size={13} color="var(--color-neutral-400)" />}
        <span className="mono" style={{ fontSize: 12, color: "var(--color-neutral-500)" }}>{e.seq}</span>
        <span className="mono" style={{ fontSize: 12, color: "var(--color-neutral-300)" }} title={fmtDate(e.ts)}>{fmtTime(e.ts, true)}</span>
        <span style={{ fontSize: 13, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={e.actor}>{e.actor}</span>
        <span className="mono" style={{ fontSize: 12, color: "var(--color-accent-300)", overflow: "hidden", textOverflow: "ellipsis" }}>{e.action}</span>
        <span style={{ fontSize: 13, color: "var(--color-neutral-200)", wordBreak: "break-word" }}>{e.subject}</span>
        <span className="mono" style={{ fontSize: 12, color: "var(--color-neutral-500)" }}>{e.hash.replace(/^sha256:/, "").slice(0, 6)}</span>
      </button>
      {open && (
        <div style={{ margin: "8px 0 14px 32px", padding: "14px 16px", borderRadius: "var(--radius-md)", background: "var(--color-surface)", boxShadow: "var(--shadow-sm)", display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
          <Detail d={e.detail} />
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", paddingTop: 10, borderTop: "1px solid var(--color-divider)", fontSize: 12, color: "var(--color-neutral-400)", alignItems: "center" }}>
            <span>
              prev <span className="mono" style={{ color: "var(--color-neutral-300)" }}>{short(e.prev)}</span>
            </span>
            <span>
              this <span className="mono" style={{ color: "var(--color-neutral-300)" }}>{short(e.hash)}</span>
            </span>
            <span style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
              {planId && (
                <button className="btn btn-secondary" style={{ fontSize: 12 }} onClick={() => router.push(`/plans/${encodeURIComponent(planId)}?from=audit`)}>
                  <ArrowSquareOut size={14} /> {t("Open plan")}
                </button>
              )}
              <button className="btn btn-secondary" style={{ fontSize: 12 }} onClick={() => copyText(JSON.stringify(e)).then(() => toast(t("Entry copied as JSON"), "neutral"))}>
                <BracketsCurly size={14} /> {t("Copy entry as JSON")}
              </button>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

const short = (h: string) => {
  const x = h.replace(/^sha256:/, "");
  return x.length > 20 ? `sha256:${x.slice(0, 12)}…${x.slice(-6)}` : h || "—";
};

function Detail({ d }: { d: Record<string, unknown> }) {
  const t = useT();
  const toast = useToast();
  const kv: [string, unknown][] = [];
  const blocks: React.ReactNode[] = [];
  for (const [k, v] of Object.entries(d)) {
    if (typeof v === "string" && (v.includes("\n") || v.length > 160)) {
      blocks.push(
        <div key={k} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ display: "flex", alignItems: "center" }}>
            <h6 className="w-h6">{k}</h6>
            <button className="btn btn-ghost" style={{ fontSize: 12, marginLeft: "auto" }} onClick={() => copyText(v).then(() => toast(t("Output copied"), "neutral"))}>
              <Copy size={13} /> {t("Copy")}
            </button>
          </div>
          <div className="mono" style={{ maxHeight: 320, overflow: "auto", padding: "10px 12px", borderRadius: "var(--radius-md)", background: "var(--color-bg)", border: "1px solid var(--color-divider)", fontSize: 12.5, lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--color-neutral-300)" }}>
            {v}
          </div>
        </div>,
      );
    } else if (Array.isArray(v) && v.length && v.every((x) => x && typeof x === "object" && "before" in x && "after" in x)) {
      blocks.push(
        <div key={k} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <h6 className="w-h6">{k}</h6>
          <div className="mono" style={{ display: "grid", gridTemplateColumns: "minmax(120px,auto) minmax(0,1fr) 16px minmax(0,1fr)", gap: "6px 10px", fontSize: 12.5 }}>
            {(v as Record<string, unknown>[]).map((c, i) => (
              <div key={i} style={{ display: "contents" }}>
                <span style={{ color: "var(--color-neutral-400)" }}>{String(c.key ?? c.path ?? (c.n != null ? `step ${c.n}` : ""))}</span>
                <span style={{ padding: "4px 8px", borderRadius: "var(--radius-sm)", background: "color-mix(in srgb, var(--color-danger) 10%, transparent)", color: "var(--color-neutral-200)", wordBreak: "break-all" }}>{fmt(c.before)}</span>
                <span style={{ color: "var(--color-neutral-500)" }}>→</span>
                <span style={{ padding: "4px 8px", borderRadius: "var(--radius-sm)", background: "color-mix(in srgb, var(--color-ok) 10%, transparent)", color: "var(--color-neutral-100)", wordBreak: "break-all" }}>{fmt(c.after)}</span>
              </div>
            ))}
          </div>
        </div>,
      );
    } else if (k === "steps" && Array.isArray(v)) {
      blocks.push(
        <div key={k} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <h6 className="w-h6">{t("Steps")}</h6>
          <div style={{ display: "grid", gridTemplateColumns: "24px minmax(0,1fr)", gap: 10 }}>
            {(v as Record<string, unknown>[]).map((s, i) => (
              <div key={i} style={{ display: "contents" }}>
                <span style={{ fontSize: 12, color: "var(--color-neutral-500)" }}>{String(s.n ?? i + 1)}</span>
                <span>
                  <span className="mono" style={{ fontSize: 13, color: "var(--color-neutral-100)", whiteSpace: "pre-wrap", display: "block" }}>{String(s.command ?? JSON.stringify(s))}</span>
                  {s.purpose != null && <span style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{String(s.purpose)}</span>}
                </span>
              </div>
            ))}
          </div>
        </div>,
      );
    } else kv.push([k, v]);
  }
  return (
    <>
      {kv.length > 0 && (
        <div style={{ display: "grid", gridTemplateColumns: "160px minmax(0,1fr)", gap: "4px 16px", fontSize: 13 }}>
          {kv.map(([k, v]) => (
            <div key={k} style={{ display: "contents" }}>
              <span style={{ color: "var(--color-neutral-400)" }}>{k}</span>
              <span className={typeof v === "object" && v !== null ? "mono" : undefined} style={{ color: "var(--color-neutral-100)", wordBreak: "break-all", fontSize: typeof v === "object" && v !== null ? 12.5 : 13 }}>
                {fmt(v)}
              </span>
            </div>
          ))}
        </div>
      )}
      {blocks}
      {!kv.length && !blocks.length && <div style={{ fontSize: 13, color: "var(--color-neutral-400)" }}>{t("No details recorded.")}</div>}
    </>
  );
}

const fmt = (v: unknown) => (v == null ? "—" : typeof v === "string" ? v : JSON.stringify(v));
