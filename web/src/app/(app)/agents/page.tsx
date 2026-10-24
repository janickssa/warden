"use client";
// Agents (spec 8): status, policy version and facts per server; Add agent with a one-time token and a
// fingerprint comparison; Revoke. Containers aren't reported by agents yet.
import { Copy, Key, Plus, SealCheck } from "@phosphor-icons/react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Dialog } from "@/components/dialog";
import { Badge, copyText, Countdown, ErrorBox, Header, Page, RelTime, Skeleton } from "@/components/ui";
import { api, ApiError, post } from "@/lib/api";
import { fmtDate, fmtTime } from "@/lib/format";
import { useT } from "@/lib/i18n";
import { useAgents, useOffline } from "@/lib/queries";
import { useToast } from "@/lib/toast";
import type { AgentToken, AgentView, EnrollmentView } from "@/lib/types";

const STATUS_BADGE: Record<string, string> = {
  online: "agent_current",
  behind: "agent_behind",
  offline: "agent_offline",
  revoked: "agent_revoked",
  not_enrolled: "agent_not_enrolled",
};

export default function Agents() {
  const t = useT();
  const q = useAgents();
  const offline = useOffline();
  const [adding, setAdding] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);
  const free = (q.data?.agents ?? []).filter((a) => a.status === "not_enrolled" || a.status === "revoked").map((a) => a.name);
  return (
    <Page max={1040}>
      <Header title={t("Agents")} sub={t("warden-agent on each server connects out over mTLS and re-checks every step against its own signed copy of the policy.")}>
        <button className="btn btn-primary" disabled={offline || !free.length} onClick={() => setAdding(true)} title={free.length ? undefined : t("Every target in targets.yaml has an agent")}>
          <Plus size={16} /> {t("Add agent")}
        </button>
      </Header>
      <ErrorBox error={q.error && !q.data ? q.error : null} />
      {q.isPending ? (
        <Skeleton height={160} />
      ) : (
        q.data?.agents.map((a) => <AgentCard key={a.name} a={a} offline={offline} onRevoke={() => setRevoking(a.name)} />)
      )}
      {adding && <AddAgent names={free} onClose={() => setAdding(false)} />}
      {revoking && <RevokeDialog name={revoking} onClose={() => setRevoking(null)} />}
    </Page>
  );
}

function Fact({ k, v, mono = true, colour }: { k: string; v: React.ReactNode; mono?: boolean; colour?: string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 3, minWidth: 0 }}>
      <span style={{ fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--color-neutral-500)" }}>{k}</span>
      <span className={mono ? "mono" : undefined} style={{ fontSize: mono ? 12.5 : 13, color: colour ?? "var(--color-neutral-100)", wordBreak: "break-all" }}>
        {v}
      </span>
    </div>
  );
}

function AgentCard({ a, offline, onRevoke }: { a: AgentView; offline: boolean; onRevoke: () => void }) {
  const t = useT();
  const revoked = a.status === "revoked";
  const policy =
    a.policy_version == null
      ? ["—", "var(--color-neutral-300)"]
      : !a.online
        ? [t("v{v} · updates on reconnect", { v: a.policy_version }), "var(--color-neutral-300)"]
        : a.policy_version >= a.latest_version
          ? [`✓ v${a.policy_version}`, "var(--color-ok)"]
          : [t("⏳ v{v} (latest v{latest})", { v: a.policy_version, latest: a.latest_version }), "var(--color-warn)"];
  return (
    <div className="card elev-sm" style={{ padding: "16px 18px", gap: 14, opacity: revoked ? 0.55 : 1 }} data-agent={a.name}>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
        <span style={{ fontSize: 18, fontWeight: 500 }}>{a.name}</span>
        {a.id && <span className="mono" style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{a.id}</span>}
        <Badge k={STATUS_BADGE[a.status] ?? a.status} />
        <span style={{ marginLeft: "auto", fontSize: 12, color: "var(--color-neutral-400)" }}>
          {revoked && a.revoked_at
            ? t("Revoked {time} · certificate revoked", { time: fmtTime(a.revoked_at) })
            : a.status === "not_enrolled"
              ? t("No agent enrolled yet")
              : a.online && a.last_seen
                ? <>{t("Last heartbeat")} <RelTime ts={a.last_seen} /></>
                : t("No heartbeat · offline")}
        </span>
        {!revoked && a.status !== "not_enrolled" && (
          <button className="btn btn-secondary" style={{ fontSize: 13 }} disabled={offline} onClick={onRevoke}>
            {t("Revoke")}
          </button>
        )}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(190px, 1fr))", gap: "12px 20px" }}>
        <Fact k={t("Host")} v={a.remote_addr ?? "—"} />
        <Fact k={t("Agent version")} v={a.agent_version ?? "—"} />
        <Fact k={t("Policy")} v={policy[0]} colour={policy[1]} />
        <Fact k={t("Workspace roots")} v={a.workspace_roots.join(", ") || "—"} />
        <Fact k={t("Kind")} v={a.kind === "lxc" ? t("LXC · unprivileged") : a.kind.toUpperCase()} mono={false} />
        <Fact k={t("Groups")} v={a.groups.join(", ") || "—"} mono={false} />
        <Fact k={t("Enrolled")} v={a.enrolled_at ? fmtDate(a.enrolled_at) : "—"} mono={false} />
        <Fact k={t("Certificate fingerprint")} v={a.fingerprint ?? "—"} />
      </div>
      {!revoked && a.status !== "not_enrolled" && (
        <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{t("No containers reported yet.")}</div>
      )}
    </div>
  );
}

function AddAgent({ names, onClose }: { names: string[]; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const [name, setName] = useState(names[0] ?? "");
  const [token, setToken] = useState<AgentToken | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const enr = useQuery({
    queryKey: ["enrollment", token?.name],
    queryFn: () => api<EnrollmentView>(`/agents/${encodeURIComponent(token!.name)}/enrollment`),
    enabled: !!token,
    refetchInterval: (q) => (q.state.data?.status === "submitted" ? false : 2000),
  });
  const submitted = enr.data?.status === "submitted";
  const expired = enr.data?.status === "expired";

  useEffect(() => {
    if (enr.data?.status === "confirmed") onClose();
  }, [enr.data?.status, onClose]);

  const create = async () => {
    setBusy(true);
    setErr(null);
    try {
      setToken(await post<AgentToken>("/agents", { name }));
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const reject = async (msg: string) => {
    if (token) await post(`/agents/${encodeURIComponent(token.name)}/reject`).catch(() => undefined);
    toast(msg, "neutral");
    qc.invalidateQueries();
    onClose();
  };
  const confirm = async () => {
    if (!token || !enr.data?.fingerprint) return;
    setBusy(true);
    try {
      const a = await post<AgentView>(`/agents/${encodeURIComponent(token.name)}/confirm`, { fingerprint: enr.data.fingerprint });
      toast(t("{name} enrolled · on policy v{v}", { name: a.name, v: a.latest_version }));
      qc.invalidateQueries();
      onClose();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : (e as Error).message);
      setBusy(false);
    }
  };

  const cmdBox: React.CSSProperties = { display: "flex", alignItems: "flex-start", gap: 8, padding: "10px 12px", borderRadius: "var(--radius-md)", background: "var(--color-bg)", fontSize: 12.5, lineHeight: 1.55 };
  let body: React.ReactNode;
  let actions: React.ReactNode;
  if (!token) {
    body = (
      <>
        <div className="dialog-body">{t("Creates a one-time enrollment token, valid for 15 min. The agent generates its own key on the server.")}</div>
        <div className="field">
          <label htmlFor="agent-name">{t("Name")}</label>
          <select id="agent-name" className="input mono" value={name} onChange={(e) => setName(e.target.value)}>
            {names.map((n) => (
              <option key={n} value={n}>
                {n}
              </option>
            ))}
          </select>
        </div>
        <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{t("Names come from targets.yaml, with the workspace roots set there.")}</div>
      </>
    );
    actions = (
      <>
        <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
          {t("Cancel")}
        </button>
        <button className="btn btn-primary" onClick={create} disabled={!name || busy}>
          <Key size={16} /> {t("Create token")}
        </button>
      </>
    );
  } else if (!submitted) {
    body = (
      <>
        <div className="dialog-body">
          {t("On")} <span className="mono">{token.name}</span>, {t("install warden-agent and run this. The token works once and expires in")} <Countdown until={token.expires_at} />.
        </div>
        <div className="mono" style={cmdBox}>
          <span style={{ flex: 1, wordBreak: "break-all" }} data-testid="enroll-command">
            {token.command}
          </span>
          <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => copyText(token.command).then(() => toast(t("Command copied"), "neutral"))}>
            <Copy size={13} /> {t("Copy")}
          </button>
        </div>
        {expired ? (
          <div style={{ fontSize: 13, color: "var(--color-warn)" }}>{t("The token expired. Create a new one.")}</div>
        ) : (
          <div style={{ fontSize: 13, color: "var(--color-accent-300)" }}>{t("◌ Waiting for warden-agent to connect…")}</div>
        )}
      </>
    );
    actions = (
      <button className="btn btn-secondary" onClick={() => reject(t("Enrollment token revoked"))}>
        {t("Revoke token")}
      </button>
    );
  } else {
    body = (
      <>
        <div className="dialog-body">
          {t("warden-agent on")} <span className="mono">{token.name}</span> {t("connected from {ip}. Compare this fingerprint with the one it printed on the server.", { ip: enr.data?.source_ip ?? "?" })}
        </div>
        <div className="mono" style={{ padding: 12, borderRadius: "var(--radius-md)", background: "var(--color-bg)", border: "1px solid var(--color-accent-700)", fontSize: 14, lineHeight: 1.5, color: "var(--color-neutral-100)", wordBreak: "break-all" }} data-testid="enroll-fingerprint">
          {enr.data?.fingerprint}
        </div>
      </>
    );
    actions = (
      <>
        <button className="btn btn-secondary" onClick={() => reject(t("Enrollment rejected · token revoked"))} disabled={busy}>
          {t("Doesn’t match · reject")}
        </button>
        <button className="btn btn-primary" onClick={confirm} disabled={busy}>
          <SealCheck size={16} /> {t("Fingerprints match · enroll")}
        </button>
      </>
    );
  }
  return (
    <Dialog title={t("Add agent")} onClose={token ? () => undefined : onClose} width={560} actions={actions} busy={!!token} testId="add-agent">
      {body}
      {err && (
        <div role="alert" style={{ fontSize: 12, color: "var(--color-danger)" }}>
          {err}
        </div>
      )}
    </Dialog>
  );
}

function RevokeDialog({ name, onClose }: { name: string; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try {
      await post(`/agents/${encodeURIComponent(name)}/revoke`);
      toast(t("{name} revoked", { name }), "neutral");
      qc.invalidateQueries();
      onClose();
    } catch (e) {
      toast((e as Error).message, "bad");
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={t("Revoke {name}?", { name })}
      onClose={onClose}
      backdropClose
      busy={busy}
      actions={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
            {t("Cancel")}
          </button>
          <button className="btn w-btn-danger" onClick={go} disabled={busy}>
            {t("Revoke agent")}
          </button>
        </>
      }
    >
      <div className="dialog-body">
        {t("Its client certificate is revoked and the connection dropped now. A plan running on {name} fails with agent_disconnected. To use the server again, enroll a new agent.", { name })}
      </div>
    </Dialog>
  );
}
