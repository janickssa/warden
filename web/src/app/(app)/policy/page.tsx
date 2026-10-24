"use client";
// Policy (spec 10): rollout, the pending loosening bundle, rules as a form or YAML, Warden's own
// classification of the change with the policy test suite, publish with a passkey, version history.
import { FileCode, Fingerprint, Key, LockSimple, SlidersHorizontal, UploadSimple } from "@phosphor-icons/react";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ChangesBox, changeLines, FieldRow, ListField, NumberField, usePublish } from "@/components/rules";
import { LiftFlow, LockdownDialog } from "@/components/shell";
import { SignatureDialog } from "@/components/signature";
import { BadgeText, ErrorBox, Header, Page, Seg, Skeleton, useDebounced } from "@/components/ui";
import { api, post } from "@/lib/api";
import { fmtExact } from "@/lib/format";
import { N, useT } from "@/lib/i18n";
import { useOffline } from "@/lib/queries";
import { useToast } from "@/lib/toast";
import type { PolicyPreview, PolicyView } from "@/lib/types";

type Doc = Record<string, unknown>;
const get = (d: Doc, path: string): unknown => path.split(".").reduce<unknown>((o, k) => (o && typeof o === "object" ? (o as Doc)[k] : undefined), d);
function set(d: Doc, path: string, v: unknown): Doc {
  const [k, ...rest] = path.split(".");
  const cur = (d[k!] && typeof d[k!] === "object" ? d[k!] : {}) as Doc;
  return { ...d, [k!]: rest.length ? set(cur, rest.join("."), v) : v };
}
const list = (d: Doc, p: string) => ((get(d, p) as string[] | undefined) ?? []).map(String);

type Field = { label: string; path: string; kind: "deny" | "allow" | "number"; unit?: string };
const SECTIONS: [string, Field[]][] = [
  [N("Paths & patterns"), [
    { label: N("Denied paths"), path: "deny_paths", kind: "deny" },
    { label: N("Deny patterns (regex, backup layer)"), path: "commands.deny_patterns", kind: "deny" },
  ]],
  [N("Commands"), [
    { label: N("git subcommands"), path: "commands.allow.git.subcommands", kind: "allow" },
    { label: N("docker subcommands"), path: "commands.allow.docker.subcommands", kind: "allow" },
    { label: N("npm subcommands"), path: "commands.allow.npm.subcommands", kind: "allow" },
    { label: N("curl denied flags"), path: "commands.allow.curl.flags_deny", kind: "deny" },
  ]],
  [N("Docker"), [
    { label: N("Allowed compose projects"), path: "docker.allowed_projects", kind: "allow" },
    { label: N("Denied containers"), path: "docker.denied_containers", kind: "deny" },
  ]],
  [N("Network"), [
    { label: N("Git hosts"), path: "network.git_hosts", kind: "allow" },
    { label: N("HTTP check hosts"), path: "network.http_check_hosts", kind: "allow" },
  ]],
  [N("Limits"), [
    { label: N("Step timeout"), path: "limits.step_timeout_s", kind: "number", unit: N("s") },
    { label: N("Steps per plan"), path: "limits.plan_max_steps", kind: "number", unit: N("steps") },
    { label: N("Output cap per step"), path: "limits.output_cap_mb", kind: "number", unit: N("MB") },
  ]],
];
const HINT = { deny: N("Adding tightens"), allow: N("Removing tightens"), number: N("Lowering tightens") };
const withoutGroups = (d: Doc) => Object.fromEntries(Object.entries(d).filter(([k]) => k !== "groups"));

export default function Policy() {
  const t = useT();
  const q = useQuery({ queryKey: ["policy"], queryFn: () => api<PolicyView>("/policy") });
  if (q.error && !q.data) return <Page max={1040}><ErrorBox error={q.error} /></Page>;
  if (!q.data) return <Page max={1040}><Header title={t("Policy")} /><Skeleton height={120} /></Page>;
  return <PolicyEditor key={JSON.stringify(q.data.document)} p={q.data} />;
}

function PolicyEditor({ p }: { p: PolicyView }) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const offline = useOffline();
  const publish = usePublish();
  const saved = withoutGroups(p.document);
  const [draft, setDraft] = useState<Doc>(saved);
  const [view, setView] = useState<"form" | "yaml">("form");
  const [dialog, setDialog] = useState<null | "sign" | "lockdown" | "lift">(null);
  const changed = JSON.stringify(draft) !== JSON.stringify(saved);
  const limitsBad = SECTIONS[4]![1].some((f) => !(Number(get(draft, f.path)) > 0));
  const body = useDebounced(changed && !limitsBad ? JSON.stringify(draft) : null, 400);
  const pv = useQuery({
    queryKey: ["policy-preview", body],
    queryFn: () => post<PolicyPreview>("/policy/preview", { document: JSON.parse(body!) }),
    enabled: !!body,
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  });
  const preview = changed && body ? pv.data : undefined;
  const previewing = changed && (pv.isFetching || body !== (changed && !limitsBad ? JSON.stringify(draft) : null));
  const cls = preview?.cls ?? "none";
  const loosen = cls === "loosen" || cls === "initial";
  const next = p.version + 1;
  const live = p.history[0];

  const text = offline
    ? t("Read-only while Warden is unreachable.")
    : limitsBad
      ? t("Limits must be greater than 0.")
      : p.pending
        ? t("A loosening bundle is waiting for its offline signature.")
        : !changed
          ? t("No changes · v{v} is live", { v: p.version })
          : previewing || !preview
            ? t("Checking the change…")
            : !preview.ok
              ? t("Fix the failing policy tests before publishing.")
              : t("Ready to publish v{v} · {cls}", { v: next, cls: loosen ? t("loosen") : t("tighten") });
  const canPublish = changed && !!preview?.ok && !!preview.preview_id && !previewing && !offline && !p.pending && !limitsBad && cls !== "none";

  const doPublish = async () => {
    if (!preview) return;
    await publish(preview, next, loosen
      ? {
          title: t("Create loosening bundle v{v}", { v: next }),
          body: t("This change loosens policy, so Warden can’t sign it alone. It creates bundle-v{v}.json; nothing changes on any agent until you upload its offline signature.", { v: next }),
          published: t("Policy v{v} published · rolling out"),
          pending: t("bundle-v{v}.json created · waiting for offline signature"),
        }
      : {
          title: t("Publish policy v{v} · ↓ tighten", { v: next }),
          body: t("Signed with the online key and pushed to every connected agent now. Approved plans that haven’t started are re-checked; running plans get the new rules from their next step."),
          published: t("Policy v{v} published · rolling out"),
          pending: t("bundle-v{v}.json created · waiting for offline signature"),
        });
  };

  const current = p.rollout.filter((r) => r.current).length;
  return (
    <Page max={1040} className="has-actionbar" style={{ gap: "var(--space-8)" }}>
      <Header title={t("Policy")} sub={live ? t("v{v} live since {at} · compiled into a signed bundle for each agent", { v: p.version, at: fmtExact(live.at) }) : t("Not published yet")}>
        {p.lockdown ? (
          <button className="btn btn-secondary" disabled={offline || !!p.pending} onClick={() => setDialog("lift")}>
            <Key size={16} /> {t("Lift lockdown…")}
          </button>
        ) : (
          <button className="btn w-btn-danger" disabled={offline} onClick={() => setDialog("lockdown")}>
            <LockSimple size={16} weight="fill" /> {t("Lockdown…")}
          </button>
        )}
      </Header>

      <div className="card elev-sm" style={{ padding: "14px 16px", gap: 10 }} data-testid="rollout">
        <div style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
          <h6 className="w-h6">{t("Rollout")}</h6>
          <span style={{ fontSize: 13, color: current === p.rollout.length ? "var(--color-ok)" : "var(--color-warn)" }}>
            {t("{n} of {m} agents on v{v}", { n: current, m: p.rollout.length, v: p.version })}
          </span>
        </div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          {p.rollout.map((r) => {
            const [txt, c] = !r.online ? [t("■ offline · v{v}", { v: r.version ?? "?" }), "danger"] : r.current ? [`✓ v${r.version}`, "ok"] : [`⏳ v${r.version ?? "?"}`, "warn"];
            return (
              <div key={r.agent} style={{ display: "flex", alignItems: "center", gap: 12, padding: "8px 12px", borderRadius: "var(--radius-md)", background: "var(--color-bg)", border: `1px solid ${c === "ok" ? "var(--color-divider)" : `color-mix(in srgb, var(--color-${c}) 40%, transparent)`}`, minWidth: 180 }}>
                <span style={{ fontSize: 14 }}>{r.agent}</span>
                <span className="mono" style={{ marginLeft: "auto", fontSize: 13, color: `var(--color-${c})` }}>{txt}</span>
              </div>
            );
          })}
        </div>
        <div style={{ fontSize: 12, color: "var(--color-neutral-500)" }}>{t("The dispatcher only sends plans to agents on the latest version. Offline agents update when they reconnect.")}</div>
      </div>

      {p.pending && (
        <div className="card" style={{ padding: "14px 16px", gap: 10, border: "1px solid color-mix(in srgb, var(--color-warn) 45%, transparent)" }} data-testid="pending-bundle">
          <div style={{ display: "flex", gap: 10, alignItems: "baseline", flexWrap: "wrap" }}>
            <span style={{ fontSize: 14, color: "var(--color-warn)" }}>{t("↑ Loosen · waiting for offline signature")}</span>
            <span className="mono" style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>bundle-v{p.pending.version}.json</span>
          </div>
          <div style={{ fontSize: 13, color: "var(--color-neutral-300)" }}>{t("Sign it on the machine that holds the offline key, then upload the signature. Nothing changes on any agent until then.")}</div>
          {changeLines({ targets: p.pending.targets } as PolicyPreview).map((l) => (
            <div key={l.text} className="mono" style={{ fontSize: 12.5, color: "var(--color-neutral-200)" }}>{l.text}</div>
          ))}
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn btn-primary" disabled={offline} onClick={() => setDialog("sign")}>
              <UploadSimple size={16} /> {t("Upload signature…")}
            </button>
            <button
              className="btn btn-secondary"
              disabled={offline}
              onClick={async () => {
                await post("/policy/pending/discard");
                toast(t("Pending bundle discarded"), "neutral");
                qc.invalidateQueries();
              }}
            >
              {t("Discard bundle")}
            </button>
          </div>
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <h6 className="w-h6">{t("Rules")}</h6>
          <span style={{ marginLeft: "auto" }} />
          <Seg name="rules-view" value={view} onChange={setView} options={[{ key: "form", label: <><SlidersHorizontal size={15} /> {t("Form")}</> }, { key: "yaml", label: <><FileCode size={15} /> {t("View YAML")}</> }]} />
        </div>
        {view === "form" ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {SECTIONS.map(([title, fields]) => (
              <div key={title} style={{ display: "flex", flexWrap: "wrap", gap: "12px 24px" }}>
                <div style={{ flex: "0 0 160px", fontSize: 16, fontWeight: 500 }}>{t(title)}</div>
                <div className="card elev-sm" style={{ flex: "1 1 480px", padding: "4px 16px", gap: 0, minWidth: 0 }}>
                  {fields.map((f, i) => (
                    <FieldRow key={f.path} label={t(f.label)} path={f.path} hint={t(HINT[f.kind])} last={i === fields.length - 1}>
                      {f.kind === "number" ? (
                        <NumberField value={Number(get(draft, f.path))} saved={Number(get(saved, f.path))} unit={t(f.unit!)} disabled={offline} onChange={(v) => setDraft((d) => set(d, f.path, v))} />
                      ) : (
                        <ListField value={list(draft, f.path)} saved={list(saved, f.path)} kind={f.kind} disabled={offline} onChange={(v) => setDraft((d) => set(d, f.path, v))} />
                      )}
                    </FieldRow>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="mono" style={{ borderRadius: "var(--radius-md)", border: "1px solid var(--color-divider)", background: "var(--color-bg)", padding: "10px 0", overflow: "auto", fontSize: 12.5, lineHeight: 1.6 }}>
            <div style={{ fontFamily: "var(--font-body)", fontSize: 12, color: "var(--color-neutral-500)", padding: "0 12px 8px" }}>
              {t("config/policy.yaml · read-only here; edit with the form or on the Warden guest")}
            </div>
            {(preview?.yaml_diff.length ? preview.yaml_diff.slice(2) : p.yaml.split("\n")).map((l, i) => {
              const diff = !!preview?.yaml_diff.length;
              const mark = diff && (l.startsWith("+") || l.startsWith("-")) ? l[0] : "";
              const body = diff ? l.slice(1) : l;
              if (diff && l.startsWith("@@")) return <div key={i} style={{ padding: "0 12px", color: "var(--color-neutral-500)" }}>{l}</div>;
              return (
                <div key={i} style={{ display: "flex", gap: 10, padding: "0 12px", background: mark === "+" ? "color-mix(in srgb, var(--color-ok) 10%, transparent)" : mark === "-" ? "color-mix(in srgb, var(--color-danger) 10%, transparent)" : undefined }}>
                  <span style={{ width: 10, flex: "none", color: mark === "+" ? "var(--color-ok)" : "var(--color-danger)" }}>{mark === "-" ? "−" : mark}</span>
                  <span style={{ whiteSpace: "pre", color: mark === "-" ? "var(--color-neutral-400)" : /^\s*[\w.-]+:/.test(body) ? "var(--color-accent-300)" : "var(--color-neutral-100)" }}>{body}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <ChangesBox
        card
        pv={preview}
        pending={changed && previewing}
        hints={{
          tighten: N("Signed with the online key and pushed to every agent within seconds."),
          loosen: N("Needs the offline key. Anything not provably tightening counts as loosening."),
          none: N("Edit the rules above to start a change."),
        }}
      />

      <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
        <h6 className="w-h6">{t("Version history")}</h6>
        {p.history.map((h) => (
          <div key={h.version} className="w-row-rule" style={{ display: "grid", gridTemplateColumns: "48px 124px 92px minmax(0,1fr)", gap: "4px 14px", padding: "10px 8px", alignItems: "baseline" }}>
            <span className="mono" style={{ fontSize: 13, color: h.version === p.version ? "var(--color-accent-300)" : "var(--color-neutral-300)" }}>v{h.version}</span>
            <span style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{fmtExact(h.at)}</span>
            <BadgeText k={h.cls === "initial" ? "loosen" : h.cls} />
            <span style={{ fontSize: 12, color: "var(--color-neutral-500)" }}>
              {t("Signed with {key} · {by} · {n} target(s)", { key: h.signed_with, by: h.by, n: h.targets })}
            </span>
          </div>
        ))}
      </div>

      <div className="w-actionbar">
        <span className="w-hint" style={{ flex: 1, fontSize: 13, color: "var(--color-neutral-400)" }} data-testid="policy-hint">{text}</span>
        <button className="btn btn-secondary" disabled={!changed} onClick={() => setDraft(saved)}>
          {t("Discard")}
        </button>
        <button className="btn btn-primary" disabled={!canPublish} onClick={doPublish} data-testid="publish">
          <Fingerprint size={16} /> {loosen ? t("Create bundle for offline signing…") : t("Publish…")}
        </button>
      </div>
      {dialog === "sign" && p.pending && <SignatureDialog mode="bundle" version={p.pending.version} onClose={() => setDialog(null)} />}
      {dialog === "lockdown" && <LockdownDialog onClose={() => setDialog(null)} />}
      {dialog === "lift" && <LiftFlow onClose={() => setDialog(null)} />}
    </Page>
  );
}
