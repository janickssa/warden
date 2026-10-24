"use client";
// Groups (spec 9): restrictions on top of the global policy, never fewer. Edits go through the same
// preview, classification and publish as the Policy page; deleting a group loosens.
import { Fingerprint, PencilSimple, Plus, Trash } from "@phosphor-icons/react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";
import { Dialog } from "@/components/dialog";
import { ChangesBox, FieldRow, ListField, NumberField, usePublish } from "@/components/rules";
import { ErrorBox, Header, Page, Seg, Skeleton, useDebounced } from "@/components/ui";
import { api, post } from "@/lib/api";
import { N, useT } from "@/lib/i18n";
import { useOffline, useStatus } from "@/lib/queries";
import type { AgentView, GroupView, PolicyPreview, PolicyView } from "@/lib/types";

type Rules = {
  read_only: { mode: "allowed" | "restricted" | "off"; deny_paths: string[] };
  commands: { deny_patterns: string[] };
  limits: { plan_max_steps: number | null; step_timeout_s: number | null; output_cap_mb: number | null };
  approvals: { passkey: boolean };
  gatekeepers: { unanimous: boolean };
};
type Draft = { name: string; desc: string; members: string[]; rules: Rules };
const EMPTY: Rules = {
  read_only: { mode: "allowed", deny_paths: [] },
  commands: { deny_patterns: [] },
  limits: { plan_max_steps: null, step_timeout_s: null, output_cap_mb: null },
  approvals: { passkey: false },
  gatekeepers: { unanimous: false },
};
const NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;
const stateColour: Record<string, string> = { online: "var(--color-ok)", behind: "var(--color-warn)", offline: "var(--color-danger)", revoked: "var(--color-neutral-500)", not_enrolled: "var(--color-neutral-500)" };

const toDraft = (g: GroupView): Draft => ({ name: g.name, desc: g.desc, members: g.members.map((m) => m.name), rules: { ...EMPTY, ...(g.rules as Partial<Rules>) } });
const toGroup = (d: Draft) => ({ desc: d.desc, members: d.members, ...d.rules, limits: Object.fromEntries(Object.entries(d.rules.limits).filter(([, v]) => v != null)) });

export default function Groups() {
  const t = useT();
  const offline = useOffline();
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<GroupView[]>("/groups") });
  const policy = useQuery({ queryKey: ["policy"], queryFn: () => api<PolicyView>("/policy") });
  const status = useStatus();
  const [editing, setEditing] = useState<string | null>(null); // group name, or "" for a new one
  const [deleting, setDeleting] = useState<GroupView | null>(null);
  const pending = !!policy.data?.pending;
  const agents = status.data?.agents ?? [];
  const globalSteps = Number((policy.data?.document as { limits?: { plan_max_steps?: number } } | undefined)?.limits?.plan_max_steps ?? 25);
  return (
    <Page max={1040}>
      <Header title={t("Groups")} sub={t("Groups add restrictions on top of the global policy and never remove any. Their rules ship in the same signed bundle, so each agent enforces them itself.")}>
        <button className="btn btn-primary" disabled={editing !== null || offline || pending} onClick={() => setEditing("")}>
          <Plus size={16} /> {t("New group")}
        </button>
      </Header>
      {pending && (
        <div className="w-box w-box--warn" style={{ fontSize: 13 }}>
          {t("A loosening bundle is waiting for its offline signature.")} <Link href="/policy">{t("Sign it on the Policy page")}</Link>
        </div>
      )}
      <ErrorBox error={groups.error && !groups.data ? groups.error : null} />
      {groups.isPending ? <Skeleton height={180} /> : null}
      {editing === "" && <Editor existing={null} all={groups.data ?? []} agents={agents} globalSteps={globalSteps} version={policy.data?.version ?? 0} onDone={() => setEditing(null)} />}
      {(groups.data ?? []).map((g) =>
        editing === g.name ? (
          <Editor key={g.name} existing={g} all={groups.data ?? []} agents={agents} globalSteps={globalSteps} version={policy.data?.version ?? 0} onDone={() => setEditing(null)} onDelete={() => setDeleting(g)} pending={pending} />
        ) : (
          <GroupCard key={g.name} g={g} agents={agents} globalSteps={globalSteps} disabled={editing !== null || offline || pending} onEdit={() => setEditing(g.name)} />
        ),
      )}
      {groups.data && !groups.data.length && editing === null && <div style={{ fontSize: 14, color: "var(--color-neutral-400)" }}>{t("No groups yet. Every agent follows the global policy.")}</div>}
      {deleting && <DeleteDialog g={deleting} version={policy.data?.version ?? 0} onClose={() => setDeleting(null)} onDone={() => { setDeleting(null); setEditing(null); }} />}
    </Page>
  );
}

function Chip({ name, kind, colour, on = true, changed, onClick }: { name: string; kind?: string; colour?: string; on?: boolean; changed?: "add" | "remove"; onClick?: () => void }) {
  const style: React.CSSProperties = {
    display: "inline-flex",
    alignItems: "center",
    gap: 6,
    padding: "4px 10px",
    borderRadius: 999,
    fontSize: 13,
    fontFamily: "inherit",
    border: `1px solid ${changed === "add" ? "color-mix(in srgb, var(--color-ok) 50%, transparent)" : changed === "remove" ? "color-mix(in srgb, var(--color-warn) 50%, transparent)" : on ? "var(--color-accent-700)" : "var(--color-divider)"}`,
    background: on ? "var(--color-accent-900)" : "transparent",
    color: on ? "var(--color-neutral-100)" : "var(--color-neutral-400)",
    cursor: onClick ? "pointer" : undefined,
  };
  const inner = (
    <>
      <span style={{ color: on ? colour : "var(--color-neutral-500)" }}>{on ? "●" : "○"}</span>
      {name}
      {kind && <span style={{ fontSize: 11, color: "var(--color-neutral-500)" }}>{kind}</span>}
    </>
  );
  return onClick ? (
    <button type="button" style={style} aria-pressed={on} onClick={onClick} data-member={name}>
      {inner}
    </button>
  ) : (
    <span style={style}>{inner}</span>
  );
}

function summary(r: Rules, globalSteps: number, t: (s: string, v?: Record<string, string | number>) => string): [string, React.ReactNode][] {
  return [
    [t("Read-only commands"), r.read_only.mode === "allowed" ? t("Allowed") : r.read_only.mode === "off" ? t("Off") : <span key="ro">{t("Restricted paths · may not read:")}<span className="mono" style={{ display: "block" }}>{r.read_only.deny_paths.join("   ")}</span></span>],
    [t("Extra deny patterns"), r.commands.deny_patterns.length ? <span key="dp" className="mono">{r.commands.deny_patterns.join("   ")}</span> : "—"],
    [t("Steps per plan"), r.limits.plan_max_steps ? t("{n} (global {g})", { n: r.limits.plan_max_steps, g: globalSteps }) : t("{g} (same as global)", { g: globalSteps })],
    [t("Approvals"), r.approvals.passkey ? t("Passkey for every approval") : <span key="ap" style={{ color: "var(--color-neutral-400)" }}>{t("Same as global")}</span>],
    [t("Gatekeepers"), r.gatekeepers.unanimous ? t("Every reviewer must allow") : <span key="gk" style={{ color: "var(--color-neutral-400)" }}>{t("Strictest verdict wins (global)")}</span>],
  ];
}

function GroupCard({ g, agents, globalSteps, disabled, onEdit }: { g: GroupView; agents: AgentView[]; globalSteps: number; disabled: boolean; onEdit: () => void }) {
  const t = useT();
  const r = { ...EMPTY, ...(g.rules as Partial<Rules>) };
  const tags = [
    r.read_only.mode === "restricted" && t("Read-only restricted"),
    r.read_only.mode === "off" && t("No read-only"),
    r.approvals.passkey && t("Passkey always"),
    r.gatekeepers.unanimous && t("Unanimous gatekeepers"),
  ].filter(Boolean) as string[];
  return (
    <div className="card elev-sm" style={{ padding: "16px 18px", gap: 14, border: "1px solid transparent" }} data-group={g.name}>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
        <span className="mono" style={{ fontSize: 18, fontWeight: 500 }}>{g.name}</span>
        <span style={{ fontSize: 13, color: "var(--color-neutral-400)" }}>{g.members.length === 1 ? t("1 member") : t("{n} members", { n: g.members.length })}</span>
        <span style={{ marginLeft: "auto", display: "flex", gap: 6, flexWrap: "wrap" }}>
          {tags.map((x) => (
            <span key={x} className="tag tag-accent">{x}</span>
          ))}
        </span>
        <button className="btn btn-secondary" style={{ fontSize: 13 }} disabled={disabled} onClick={onEdit}>
          <PencilSimple size={15} /> {t("Edit")}
        </button>
      </div>
      {g.desc && <div style={{ fontSize: 14, color: "var(--color-neutral-300)" }}>{g.desc}</div>}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {g.members.map((m) => (
          <Chip key={m.name} name={m.name} kind={m.kind} colour={stateColour[agents.find((a) => a.name === m.name)?.status ?? "not_enrolled"]} />
        ))}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(160px,220px) minmax(0,1fr)", gap: "8px 16px", fontSize: 13 }}>
        {summary(r, globalSteps, t).map(([k, v]) => (
          <div key={k} style={{ display: "contents" }}>
            <span style={{ color: "var(--color-neutral-400)" }}>{k}</span>
            <span style={{ wordBreak: "break-word" }}>{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Editor({ existing, all, agents, globalSteps, version, onDone, onDelete, pending }: { existing: GroupView | null; all: GroupView[]; agents: AgentView[]; globalSteps: number; version: number; onDone: () => void; onDelete?: () => void; pending?: boolean }) {
  const t = useT();
  const offline = useOffline();
  const publish = usePublish();
  const saved: Draft = existing ? toDraft(existing) : { name: "", desc: "", members: [], rules: EMPTY };
  const [d, setD] = useState<Draft>(saved);
  const changed = JSON.stringify(d) !== JSON.stringify(saved);
  const errors: string[] = [];
  if (!existing && d.name && !NAME.test(d.name)) errors.push(t("Name: lowercase letters, numbers and dashes."));
  if (!existing && all.some((g) => g.name === d.name)) errors.push(t("A group with that name already exists."));
  const steps = d.rules.limits.plan_max_steps;
  if (steps != null && !(steps >= 1 && steps <= globalSteps)) errors.push(t("Steps per plan must be 1–{g}. Groups can’t exceed the global limit.", { g: globalSteps }));
  if (d.rules.read_only.mode === "restricted" && !d.rules.read_only.deny_paths.length) errors.push(t("Restricted read-only needs at least one path."));
  const ready = changed && !errors.length && (!!existing || NAME.test(d.name));
  const key = useDebounced(ready ? JSON.stringify(d) : null, 400);
  const pv = useQuery({
    queryKey: ["group-preview", existing?.name ?? "", key],
    queryFn: () => post<PolicyPreview>("/groups/preview", { name: d.name, group: toGroup(JSON.parse(key!) as Draft) }),
    enabled: !!key,
    placeholderData: keepPreviousData,
    staleTime: 60_000,
  });
  const preview = ready && key ? pv.data : undefined;
  const busy = ready && (pv.isFetching || key !== JSON.stringify(d));
  const cls = preview?.cls ?? "none";
  const loosen = cls === "loosen" || cls === "initial";
  const next = version + 1;
  const setR = (f: (r: Rules) => Rules) => setD((x) => ({ ...x, rules: f(x.rules) }));
  const toggle = (name: string) => setD((x) => ({ ...x, members: x.members.includes(name) ? x.members.filter((m) => m !== name) : [...x.members, name] }));
  const go = async () => {
    if (!preview) return;
    const what = existing ? t("Update group {name}", { name: d.name }) : t("Create group {name}", { name: d.name });
    const r = await publish(preview, next, loosen
      ? {
          title: t("Create loosening bundle v{v}", { v: next }),
          body: t("This relaxes group {name}, so Warden can’t sign it alone. Upload the offline signature on the Policy page to publish it.", { name: d.name }),
          published: `${what} · ${t("v{v} rolling out")}`,
          pending: t("bundle-v{v}.json created · sign it on the Policy page"),
        }
      : {
          title: t("Publish policy v{v} · ↓ tighten", { v: next }),
          body: t("Group {name} only gets stricter, so the online key signs it and every member agent gets it now.", { name: d.name }),
          published: `${what} · ${t("v{v} rolling out")}`,
          pending: t("bundle-v{v}.json created · sign it on the Policy page"),
        });
    if (r) onDone();
  };
  const names = [...new Set([...agents.map((a) => a.name), ...saved.members])];
  const yesNo = (id: string, v: boolean, f: (v: boolean) => void) => <Seg name={`${existing?.name ?? "new"}-${id}`} value={v ? "on" : "off"} onChange={(k) => f(k === "on")} options={[{ key: "off", label: t("Off") }, { key: "on", label: t("On") }]} />;
  return (
    <div className="card elev-sm" style={{ padding: "16px 18px", gap: 14, border: "1px solid var(--color-accent-700)" }} data-testid="group-editor">
      {existing ? (
        <span className="mono" style={{ fontSize: 18, fontWeight: 500 }}>{existing.name}</span>
      ) : (
        <>
          <input className="input mono" style={{ maxWidth: 240 }} placeholder="group-name" aria-label={t("Group name")} value={d.name} onChange={(e) => setD({ ...d, name: e.target.value })} />
        </>
      )}
      <input className="input" placeholder={t("What these servers are, e.g. LXC containers with secrets")} aria-label={t("Description")} value={d.desc} onChange={(e) => setD({ ...d, desc: e.target.value })} />
      <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{t("Members · click to add or remove. Adding tightens, removing loosens.")}</div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {names.map((n) => {
          const on = d.members.includes(n);
          const was = saved.members.includes(n);
          return <Chip key={n} name={n} on={on} colour={stateColour[agents.find((a) => a.name === n)?.status ?? "not_enrolled"]} changed={on && !was ? "add" : !on && was ? "remove" : undefined} onClick={() => toggle(n)} />;
        })}
      </div>
      <div>
        <FieldRow label={t("Read-only commands")} path="read_only.mode" hint={t("Stricter to the right")}>
          <Seg name={`ro-${d.name}`} value={d.rules.read_only.mode} onChange={(m) => setR((r) => ({ ...r, read_only: { ...r.read_only, mode: m } }))} options={[{ key: "allowed", label: t("Allowed") }, { key: "restricted", label: t("Restricted paths") }, { key: "off", label: t("Off") }]} />
        </FieldRow>
        {d.rules.read_only.mode === "restricted" && (
          <FieldRow label={t("Read-only commands may not read")} path="read_only.deny_paths" hint={t("Adding tightens")}>
            <ListField surface kind="deny" value={d.rules.read_only.deny_paths} saved={saved.rules.read_only.deny_paths} placeholder={t("e.g. /home")} onChange={(v) => setR((r) => ({ ...r, read_only: { ...r.read_only, deny_paths: v } }))} />
          </FieldRow>
        )}
        <FieldRow label={t("Extra deny patterns for plan steps")} path="commands.deny_patterns" hint={t("Adding tightens")}>
          <ListField surface kind="deny" value={d.rules.commands.deny_patterns} saved={saved.rules.commands.deny_patterns} placeholder={t("regex, e.g. docker\\s+exec")} onChange={(v) => setR((r) => ({ ...r, commands: { deny_patterns: v } }))} />
        </FieldRow>
        <FieldRow label={t("Steps per plan")} path="limits.plan_max_steps" hint={t("Lowering tightens · global is {g}", { g: globalSteps })}>
          <NumberField value={d.rules.limits.plan_max_steps ?? globalSteps} saved={saved.rules.limits.plan_max_steps ?? globalSteps} unit={t("steps")} onChange={(v) => setR((r) => ({ ...r, limits: { ...r.limits, plan_max_steps: Number.isFinite(v) && v !== globalSteps ? v : null } }))} />
        </FieldRow>
        <FieldRow label={t("Every approval needs a passkey")} path="approvals.passkey" hint={t("On tightens")}>
          {yesNo("passkey", d.rules.approvals.passkey, (v) => setR((r) => ({ ...r, approvals: { passkey: v } })))}
        </FieldRow>
        <FieldRow label={t("All gatekeepers must allow")} path="gatekeepers.unanimous" hint={t("On tightens · one escalate blocks Approve")} last>
          {yesNo("unanimous", d.rules.gatekeepers.unanimous, (v) => setR((r) => ({ ...r, gatekeepers: { unanimous: v } })))}
        </FieldRow>
      </div>
      <ChangesBox
        pv={preview}
        pending={busy}
        errors={errors}
        hints={{ tighten: N("Only adds restrictions · online key, live in seconds"), loosen: N("Relaxes the group · needs the offline key"), none: N("Edit the group to start a change") }}
      />
      <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", flexWrap: "wrap" }}>
        {existing && (
          <button className="btn btn-ghost" style={{ color: "var(--color-danger)", marginRight: "auto" }} disabled={offline || pending} onClick={onDelete}>
            <Trash size={15} /> {t("Delete group…")}
          </button>
        )}
        <button className="btn btn-secondary" onClick={onDone}>
          {t("Cancel")}
        </button>
        <button className="btn btn-primary" disabled={!preview?.ok || !preview.preview_id || busy || offline || pending || cls === "none"} onClick={go}>
          <Fingerprint size={16} /> {loosen ? t("Create bundle for offline signing…") : existing ? t("Publish…") : t("Create & publish…")}
        </button>
      </div>
    </div>
  );
}

function DeleteDialog({ g, version, onClose, onDone }: { g: GroupView; version: number; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const offline = useOffline();
  const publish = usePublish();
  const [busy, setBusy] = useState(false);
  const r = { ...EMPTY, ...(g.rules as Partial<Rules>) };
  const removed = [
    r.read_only.mode === "restricted" && t("Read-only commands: Restricted paths ({paths})", { paths: r.read_only.deny_paths.join(", ") }),
    r.read_only.mode === "off" && t("Read-only commands: Off"),
    r.commands.deny_patterns.length && t("{n} extra deny patterns", { n: r.commands.deny_patterns.length }),
    r.limits.plan_max_steps && t("Steps per plan capped at {n}", { n: r.limits.plan_max_steps }),
    r.approvals.passkey && t("Passkey for every approval"),
    r.gatekeepers.unanimous && t("All gatekeepers must allow"),
  ].filter(Boolean) as string[];
  const next = version + 1;
  const go = async () => {
    setBusy(true);
    try {
      const pv = await post<PolicyPreview>("/groups/preview", { name: g.name, group: null });
      const res = await publish(pv, next, {
        title: t("Create loosening bundle v{v}", { v: next }),
        body: t("Deleting {name} removes its restrictions from {n} agents. Warden can’t sign that alone; upload the offline signature on the Policy page.", { name: g.name, n: g.members.length }),
        published: t("Delete group {name} · v{v} rolling out", { name: g.name }),
        pending: t("bundle-v{v}.json created · waiting for offline signature"),
      });
      if (res) onDone();
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={<>{t("Delete group")} <span className="mono">{g.name}</span>?</>}
      onClose={onClose}
      backdropClose
      busy={busy}
      width={500}
      actions={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>{t("Cancel")}</button>
          <button className="btn w-btn-danger" onClick={go} disabled={busy || offline}>
            <Trash size={15} /> {t("Delete & create bundle…")}
          </button>
        </>
      }
    >
      <div className="dialog-body">{t("These agents lose the group’s restrictions. Deleting counts as loosening, so it needs the offline key. Nothing changes on any agent until the signature is uploaded.")}</div>
      <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{t("Members losing these restrictions")}</div>
      {g.members.length ? (
        g.members.map((m) => (
          <div key={m.name} style={{ padding: "6px 10px", borderRadius: "var(--radius-md)", background: "var(--color-bg)", fontSize: 13 }}>
            <span className="mono">{m.name}</span> <span style={{ color: "var(--color-neutral-500)" }}>{m.kind}</span>
          </div>
        ))
      ) : (
        <div style={{ fontSize: 13 }}>{t("No members. No agent changes.")}</div>
      )}
      <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{t("Restrictions removed")}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 13, color: "var(--color-neutral-300)" }}>
        {(removed.length ? removed : [t("None beyond the global policy")]).map((x) => (
          <span key={x}>· {x}</span>
        ))}
      </div>
    </Dialog>
  );
}
