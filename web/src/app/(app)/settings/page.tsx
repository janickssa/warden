"use client";
// Settings (spec 12). Only the human-facing keys Warden lists as editable can change here; every save is
// audited with before and after. End-to-end signing ships in signed bundles, so it has its own passkey
// flow. Claude can't read or change any of this: there is no MCP tool for it.
import { Certificate, Desktop, DeviceMobile, FloppyDisk, Key, Laptop, LockSimple, Plus, SealCheck, Usb } from "@phosphor-icons/react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { confirmOptions, isCancel, usePasskey } from "@/components/passkey";
import { ErrorBox, Header, Page, Seg, Skeleton } from "@/components/ui";
import { api, ApiError, post, put } from "@/lib/api";
import { fmtDate, fmtExact, fmtTime } from "@/lib/format";
import { N, useT } from "@/lib/i18n";
import { useOffline } from "@/lib/queries";
import { useToast } from "@/lib/toast";
import type { PasskeyView, PublishResult, SessionView, SettingsView } from "@/lib/types";
import { createCredential } from "@/lib/webauthn";

type Values = Record<string, unknown>;

export default function Settings() {
  const t = useT();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api<SettingsView>("/settings") });
  if (q.error && !q.data) return <Page max={860}><ErrorBox error={q.error} /></Page>;
  if (!q.data) return <Page max={860}><Header title={t("Settings")} /><Skeleton height={140} /></Page>;
  return <Editor key={JSON.stringify(q.data.values)} s={q.data} />;
}

function Section({ title, desc, children }: { title: string; desc: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: "12px 24px" }}>
      <div style={{ flex: "0 0 200px" }}>
        <div style={{ fontSize: 16, fontWeight: 500 }}>{title}</div>
        <div style={{ fontSize: 12, lineHeight: 1.5, color: "var(--color-neutral-400)" }}>{desc}</div>
      </div>
      <div className="card elev-sm" style={{ flex: "1 1 420px", padding: "4px 16px", gap: 0, minWidth: 0 }}>
        {children}
      </div>
    </div>
  );
}

function Row({ label, help, warn, children }: { label: string; help?: string; warn?: string; children: React.ReactNode }) {
  return (
    <div className="w-set-row" style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap", padding: "12px 0", borderBottom: "1px solid var(--color-divider)" }}>
      <div style={{ flex: 1, minWidth: 200 }}>
        <div style={{ fontSize: 14 }}>{label}</div>
        {help && <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{help}</div>}
        {warn && <div style={{ fontSize: 12, color: "var(--color-warn)" }}>▲ {warn}</div>}
      </div>
      {children}
    </div>
  );
}

const Locked = ({ v }: { v: string }) => (
  <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 13, color: "var(--color-neutral-300)" }}>
    <LockSimple size={14} color="var(--color-neutral-500)" /> {v}
  </span>
);

function Editor({ s }: { s: SettingsView }) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const offline = useOffline();
  const passkey = usePasskey();
  const [draft, setDraft] = useState<Values>(s.values);
  const [saving, setSaving] = useState(false);
  const dirty = Object.keys(draft).filter((k) => JSON.stringify(draft[k]) !== JSON.stringify(s.values[k]));
  const invalid = ["approvals.expiry_min", "approvals.chat_max_steps"].some((k) => !(Number(draft[k]) > 0));
  const set = (k: string, v: unknown) => setDraft((d) => ({ ...d, [k]: v }));
  const seg = (k: string, opts: [unknown, string][], unit?: string) => (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <Seg name={k} value={String(draft[k])} onChange={(v) => set(k, opts.find(([o]) => String(o) === v)![0])} options={opts.map(([o, l]) => ({ key: String(o), label: t(l) }))} />
      {unit && <span style={{ fontSize: 13, color: "var(--color-neutral-400)" }}>{t(unit)}</span>}
    </span>
  );
  const num = (k: string, unit: string, max: number) => (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
      <input type="number" className="input" min={1} max={max} style={{ width: 96 }} aria-label={k} value={Number.isFinite(draft[k] as number) ? String(draft[k]) : ""} onChange={(e) => set(k, e.target.value === "" ? NaN : Number(e.target.value))} />
      <span style={{ fontSize: 13, color: "var(--color-neutral-400)", minWidth: 36 }}>{t(unit)}</span>
    </span>
  );
  const onOff = (k: string) => seg(k, [[true, N("On")], [false, N("Off")]]);

  const save = async () => {
    setSaving(true);
    try {
      await put<SettingsView>("/settings", { changes: Object.fromEntries(dirty.map((k) => [k, draft[k]])) });
      toast(dirty.length === 1 ? t("Saved · 1 change written to the audit log") : t("Saved · {n} changes written to the audit log", { n: dirty.length }));
      qc.invalidateQueries();
    } catch (e) {
      toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
    } finally {
      setSaving(false);
    }
  };

  const setE2E = async (enabled: boolean) => {
    try {
      const r = await passkey({
        title: enabled ? t("Turn on end-to-end signing") : t("Turn off end-to-end signing"),
        body: enabled
          ? t("Agents will only run plans your passkey signed. This tightens, so it ships at once.")
          : t("Agents will accept Warden’s approval key again. This loosens, so it waits for the offline signature on the Policy page."),
        options: () => confirmOptions("settings", "e2e"),
        submit: (signed) => post<PublishResult>("/e2e", { enabled, ...signed }),
      });
      toast(r.outcome === "pending" ? t("bundle-v{v}.json created · waiting for offline signature", { v: r.version }) : t("Policy v{v} published · rolling out", { v: r.version }), r.outcome === "pending" ? "neutral" : "ok");
      qc.invalidateQueries();
    } catch (e) {
      if (!isCancel(e)) toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
    }
  };

  const gk = s.gatekeepers as { timeout_s?: number; reviewers?: { name: string; model: string; send_untrusted_output: boolean }[]; mode?: string };
  const lim = s.limits as { step_timeout_s?: number; plan_max_steps?: number; output_cap_mb?: number; kill?: string };
  const hint = offline
    ? [t("Read-only while Warden is unreachable."), "var(--color-neutral-400)"]
    : invalid
      ? [t("Numbers must be greater than 0."), "var(--color-danger)"]
      : dirty.length
        ? [`${dirty.length === 1 ? t("1 unsaved change") : t("{n} unsaved changes", { n: dirty.length })} · ${dirty.join(", ")}`, "var(--color-accent-300)"]
        : [t("All changes saved."), "var(--color-neutral-400)"];

  return (
    <Page max={860} className="has-actionbar" style={{ paddingBottom: 0, gap: "var(--space-8)" }}>
      <Header title={t("Settings")} sub={t("Every change is written to the audit log with its before and after values. Claude can’t read or change these.")} />

      <Section title={t("Retention")} desc={t("How long history is kept. Pruned ranges leave a signed checkpoint, so the hash chain still verifies.")}>
        <Row label={t("Audit log entries")} help={t("Proposals, verdicts, approvals, plan diffs and settings changes.")}>
          {seg("retention.audit_days", [[30, "30"], [90, "90"], [180, "180"], [365, "365"], [0, N("Forever")]], N("days"))}
        </Row>
        <Row label={t("Command output")} help={t("Full stdout and stderr of every step and read-only command, capped per step.")}>
          {seg("retention.output_days", [[7, "7"], [30, "30"], [90, "90"], [180, "180"], [0, N("Forever")]], N("days"))}
        </Row>
        <Row label={t("JSONL export")} help={t("Rotated append-only files for off-box backup.")}>
          {seg("retention.export", [["daily", N("Daily")], ["weekly", N("Weekly")], ["off", N("Off")]])}
        </Row>
        <Row label={t("Export folder")}>
          <input className="input mono" style={{ maxWidth: 300, fontSize: 13 }} aria-label="retention.export_dir" value={String(draft["retention.export_dir"] ?? "")} onChange={(e) => set("retention.export_dir", e.target.value)} />
        </Row>
      </Section>

      <Section title={t("Approvals")} desc={t("How plans reach you and how long they wait.")}>
        <Row label={t("Plan expires after")} help={t("Unanswered plans expire and Claude has to propose again.")}>
          {num("approvals.expiry_min", N("min"), 1440)}
        </Row>
        <Row label={t("Passkey for high-risk plans")}>
          <Locked v={t("Always required")} />
        </Row>
        <Row label={t("Sign approvals with your passkey")} help={t("Agents verify that you approved, not just Warden. Every approval then needs your passkey, and chat approval hands off to the dashboard or app to sign.")}>
          <span data-testid="e2e">
            <Seg name="e2e" value={s.e2e ? "on" : "off"} onChange={(v) => !offline && setE2E(v === "on")} options={[{ key: "on", label: t("On") }, { key: "off", label: t("Off") }]} />
          </span>
        </Row>
        <Row label={t("Passkey for medium-risk plans")}>{onOff("approvals.passkey_medium")}</Row>
        <Row label={t("Chat approval")} help={t("Clients that can’t ask you in chat get a dashboard link instead.")}>
          {onOff("approvals.chat")}
        </Row>
        <Row label={t("Longest plan shown in chat")} help={t("Longer plans show a summary and a dashboard link.")}>
          {num("approvals.chat_max_steps", N("steps"), 100)}
        </Row>
        <Row label={t("Approve all")}>
          <Locked v={t("Not available, by design")} />
        </Row>
      </Section>

      <Section title={t("Gatekeepers")} desc={t("Reviewers can only make a verdict stricter, never override a policy deny. Set in gatekeeper.yaml on the Warden guest.")}>
        <Row label={t("Mode")}>
          <Locked v={t("Strictest verdict wins")} />
        </Row>
        <Row label={t("Reviewer timeout")} help={t("A timeout counts as escalate for that reviewer.")}>
          <Locked v={`${gk.timeout_s ?? "?"} s`} />
        </Row>
        {(gk.reviewers ?? []).map((r) => (
          <Row key={r.name} label={t("Send command output to {name}", { name: r.name })} help={r.model}>
            <Locked v={r.send_untrusted_output ? t("On") : t("Off")} />
          </Row>
        ))}
        <Row label={t("Scrub secrets before sending")}>
          <Locked v={t("Always on")} />
        </Row>
      </Section>

      <Section title={t("Execution limits")} desc={t("Part of the policy. Change them on the Policy page; agents enforce them.")}>
        <Row label={t("Step timeout")}><Locked v={`${lim.step_timeout_s ?? "?"} s`} /></Row>
        <Row label={t("Steps per plan")}><Locked v={t("{n} max", { n: lim.plan_max_steps ?? "?" })} /></Row>
        <Row label={t("Output cap")}><Locked v={t("{n} MB per step", { n: lim.output_cap_mb ?? "?" })} /></Row>
        <Row label={t("Kill switch")}><Locked v={t("SIGTERM, then SIGKILL after 10 s")} /></Row>
      </Section>

      <Section title={t("Schedules")} desc={t("Pre-approved templates that run on a cron.")}>
        <Row label={t("New schedules expire after")}>{seg("schedules.default_expiry_days", [[30, "30"], [90, "90"], [180, "180"]], N("days"))}</Row>
      </Section>

      <Section title={t("iPhone notifications")} desc={t("Push goes through Apple, so it arrives even with WireGuard off.")}>
        <Row label={t("Approval needed")}>{onOff("notifications.approval_needed")}</Row>
        <Row label={t("Plan failed")}>{onOff("notifications.plan_failed")}</Row>
        <Row label={t("Scheduled run finished")}>{onOff("notifications.scheduled_done")}</Row>
        <Row label={t("Agent refused a step")} help={t("An agent blocked a step or read-only command because of policy.")}>
          {onOff("notifications.agent_refused")}
        </Row>
      </Section>

      <Section title={t("Language & time")} desc={t("Applies to the dashboard and the app.")}>
        <Row label={t("Language")}>{seg("ui.language", [["en", N("English")], ["da", N("Dansk")]])}</Row>
        <Row label={t("Time zone")}><Locked v="Europe/Copenhagen" /></Row>
        <Row label={t("Time format")}><Locked v={t("24-hour · 20.10.2026 14:32")} /></Row>
        <Row label={t("Units")}><Locked v={t("Metric · MB/GB, seconds")} /></Row>
      </Section>

      <Keys s={s} />
      <Passkeys />

      <div className="w-actionbar">
        <span className="w-hint" style={{ flex: 1, fontSize: 13, color: hint[1] }} data-testid="settings-hint">{hint[0]}</span>
        <button className="btn btn-secondary" disabled={!dirty.length || saving} onClick={() => setDraft(s.values)}>
          {t("Discard")}
        </button>
        <button className="btn btn-primary" disabled={!dirty.length || invalid || offline || saving} onClick={save}>
          <FloppyDisk size={16} /> {t("Save changes")}
        </button>
      </div>
    </Page>
  );
}

const KEY_NAMES = [N("Approval key"), N("Online policy key")];

function Keys({ s }: { s: SettingsView }) {
  void KEY_NAMES;
  const t = useT();
  const ca = s.ca as { fingerprint?: string; expires_at?: string };
  const days = ca.expires_at ? Math.round((new Date(ca.expires_at).getTime() - Date.now()) / 86_400_000) : null;
  const hasBackup = s.keys.some((k) => k.role === "backup");
  const hasOffline = s.keys.some((k) => k.role);
  const fp = (k: string) => (k.length > 24 ? `${k.slice(0, 13)}…${k.slice(-4)}` : k);
  const row = (icon: React.ReactNode, name: string, value: string, meta: string, status?: [string, string]) => (
    <div key={name} style={{ display: "flex", flexDirection: "column", gap: 8, padding: "12px 0", borderBottom: "1px solid var(--color-divider)" }}>
      <div style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
        <span style={{ color: "var(--color-neutral-300)", marginTop: 2 }}>{icon}</span>
        <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
          <span style={{ fontSize: 14 }}>{name}</span>
          <span className="mono" style={{ fontSize: 12.5, wordBreak: "break-all" }} title={value}>{value}</span>
          <span style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{meta}</span>
        </div>
      </div>
      {status && <div style={{ fontSize: 12, lineHeight: 1.5, color: status[1] }}>{status[0]}</div>}
    </div>
  );
  return (
    <Section title={t("Signing keys")} desc={t("Public halves only. The offline key never touches a server. Agents learn new keys through the next signed bundle.")}>
      {s.keys.map((k) =>
        row(
          k.role ? <Usb size={20} /> : k.name.startsWith("Approval") ? <SealCheck size={20} /> : <Key size={20} />,
          k.role === "backup" ? t("Backup offline key") : k.role ? t("Offline policy key") : t(k.name),
          fp(k.key_id),
          k.role ? t("signs loosening bundles · never on a server") : k.name.startsWith("Approval") ? t("warden guest · signs plan approvals") : t("warden guest · signs tightening bundles"),
        ),
      )}
      {!hasOffline && row(<Usb size={20} />, t("Offline policy key"), t("Not registered"), t("Register with warden keys offline register on the Warden guest"), [t("▲ Without an offline key nothing can be loosened."), "var(--color-warn)"])}
      {hasOffline && !hasBackup && row(<Usb size={20} />, t("Backup offline key"), t("Not registered"), t("A second key that can replace the offline key if it’s lost"), [t("▲ No backup registered. If the offline key is lost, nothing can be loosened and the offline key can’t be replaced."), "var(--color-warn)"])}
      {row(
        <Certificate size={20} />,
        t("Internal CA"),
        ca.fingerprint ? fp(ca.fingerprint) : "warden-ca",
        ca.expires_at ? t("Expires {date} · in {n} days · issues agent client certificates", { date: fmtDate(ca.expires_at), n: days ?? "?" }) : "",
        days != null && days < 90 ? [t("▲ Expires in {n} days. Renew before then or agents can’t reconnect.", { n: days }), "var(--color-warn)"] : undefined,
      )}
    </Section>
  );
}

function Passkeys() {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const offline = useOffline();
  const passkey = usePasskey();
  const keys = useQuery({ queryKey: ["passkeys"], queryFn: () => api<PasskeyView[]>("/passkeys") });
  const sessions = useQuery({ queryKey: ["sessions"], queryFn: () => api<SessionView[]>("/sessions") });
  const [name, setName] = useState("");
  const [adding, setAdding] = useState(false);

  const remove = async (k: PasskeyView) => {
    try {
      await passkey({
        title: t("Remove passkey “{name}”", { name: k.name }),
        body: t("Its sessions are signed out and agents stop accepting its approvals with the next bundle."),
        options: () => confirmOptions("remove_passkey", k.credential_id),
        submit: (signed) => post(`/passkeys/${encodeURIComponent(k.credential_id)}/remove`, signed),
      });
      toast(t("{device} revoked · its sessions are signed out", { device: k.name }), "neutral");
      qc.invalidateQueries();
    } catch (e) {
      if (!isCancel(e)) toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
    }
  };
  const register = async () => {
    const n = name.trim();
    if (!n) return;
    try {
      const signed = await passkey({
        title: t("Confirm with your passkey"),
        body: t("Adding a passkey named “{name}”. Confirm with a passkey you already have, then create the new one.", { name: n }),
        options: () => confirmOptions("add_passkey", n),
        submit: async (s) => s,
      });
      toast(t("Follow your browser’s passkey prompt to register a new device"), "neutral");
      const o = await post<{ challenge_id: string; options: Record<string, unknown> }>("/passkeys/register/options", { name: n, confirm: signed });
      const credential = await createCredential(o.options);
      const r = await post<{ name: string; approvers?: string }>("/passkeys/register", { challenge_id: o.challenge_id, credential });
      toast(r.approvers?.startsWith("pending") ? t("Passkey “{name}” added · sign the approver list on the Policy page", { name: r.name }) : t("Passkey “{name}” added", { name: r.name }));
      setName("");
      setAdding(false);
      qc.invalidateQueries();
    } catch (e) {
      if (!isCancel(e)) toast(e instanceof ApiError ? e.message : (e as Error).message, "bad");
    }
  };
  const revokeSession = async (s: SessionView) => {
    try {
      await post(`/sessions/${encodeURIComponent(s.id)}/revoke`);
      toast(t("{device} signed out", { device: s.name }), "neutral");
      qc.invalidateQueries({ queryKey: ["sessions"] });
    } catch (e) {
      toast((e as Error).message, "bad");
    }
  };
  const icon = (ua: string) => (/iPhone|Android|Mobile/.test(ua) ? <DeviceMobile size={20} /> : /Mac|Windows|Linux/.test(ua) ? <Laptop size={20} /> : <Desktop size={20} />);
  const rowStyle: React.CSSProperties = { display: "flex", alignItems: "center", gap: 12, padding: "12px 0", borderBottom: "1px solid var(--color-divider)" };
  return (
    <Section title={t("Passkeys & sessions")} desc={t("Approval only comes from these. The MCP connection authenticates separately.")}>
      {(keys.data ?? []).map((k) => (
        <div key={k.credential_id} style={rowStyle} data-passkey={k.name}>
          <Key size={20} color="var(--color-neutral-300)" />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 14 }}>{t("Passkey “{name}”", { name: k.name })}</div>
            <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>
              {t("registered {date}", { date: fmtDate(k.created_at) })} · {k.last_used_at ? t("last used {time}", { time: fmtExact(k.last_used_at) }) : t("never used")} · {k.alg === -8 ? "Ed25519" : "ES256"}
            </div>
          </div>
          <button className="btn btn-secondary" style={{ fontSize: 13 }} disabled={offline || (keys.data?.length ?? 0) < 2} title={(keys.data?.length ?? 0) < 2 ? t("Your only passkey can’t be removed") : undefined} onClick={() => remove(k)}>
            {t("Remove")}
          </button>
        </div>
      ))}
      {(sessions.data ?? []).map((s) => (
        <div key={s.id} style={rowStyle} data-session={s.id}>
          <span style={{ color: "var(--color-neutral-300)" }}>{icon(s.user_agent)}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 14 }}>{t("Session · passkey “{name}”", { name: s.name })}</div>
            <div style={{ fontSize: 12, color: "var(--color-neutral-400)", overflow: "hidden", textOverflow: "ellipsis" }}>
              {t("signed in {time}", { time: fmtTime(s.created_at) })} · {s.ip} · {t("last seen {time}", { time: fmtTime(s.last_seen_at) })}
            </div>
          </div>
          {s.current ? (
            <span className="tag tag-accent">{t("This session")}</span>
          ) : (
            <button className="btn btn-secondary" style={{ fontSize: 13 }} disabled={offline} onClick={() => revokeSession(s)}>
              {t("Revoke")}
            </button>
          )}
        </div>
      ))}
      <div style={{ display: "flex", gap: 8, padding: "12px 0", flexWrap: "wrap", alignItems: "center" }}>
        {adding ? (
          <>
            <input className="input" style={{ maxWidth: 220 }} placeholder={t("Device name, e.g. iPhone")} aria-label={t("Passkey name")} maxLength={40} value={name} onChange={(e) => setName(e.target.value)} onKeyDown={(e) => e.key === "Enter" && register()} />
            <button className="btn btn-primary" style={{ fontSize: 13 }} disabled={!name.trim() || offline} onClick={register}>
              {t("Register")}
            </button>
            <button className="btn btn-ghost" style={{ fontSize: 13 }} onClick={() => setAdding(false)}>
              {t("Cancel")}
            </button>
          </>
        ) : (
          <button className="btn btn-secondary" style={{ fontSize: 13 }} disabled={offline} onClick={() => setAdding(true)}>
            <Plus size={15} /> {t("Register passkey")}
          </button>
        )}
      </div>
    </Section>
  );
}
