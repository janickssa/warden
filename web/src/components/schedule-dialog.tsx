"use client";
// "Save as schedule" (README 17.3 Schedules): a succeeded plan becomes a template that needs its own
// approval, with a passkey, before it can run.
import { ClockClockwise } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ApiError, post } from "@/lib/api";
import { CRON_PRESETS, describeCron } from "@/lib/cron";
import { useT } from "@/lib/i18n";
import { useToast } from "@/lib/toast";
import type { PlanDetail, ScheduleView } from "@/lib/types";
import { Dialog } from "./dialog";
import { Seg } from "./ui";

const NAME = /^[a-z0-9][a-z0-9-]{0,62}$/;

export function SaveScheduleDialog({ p, onClose }: { p: PlanDetail; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const router = useRouter();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [preset, setPreset] = useState<string>(CRON_PRESETS[0]!.cron);
  const [custom, setCustom] = useState("");
  const [days, setDays] = useState<"30" | "90" | "180">("90");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const cron = preset === "custom" ? custom.trim() : preset;
  const nameOk = NAME.test(name);
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      const s = await post<ScheduleView>(`/plans/${encodeURIComponent(p.id)}/schedule`, { name, cron, days: Number(days) });
      toast(t("Template saved · it needs its own approval before it can run"), "neutral");
      qc.invalidateQueries();
      router.push(`/schedules/${encodeURIComponent(s.id)}`);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : (e as Error).message);
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={
        <>
          <ClockClockwise size={20} /> {t("Save as schedule")}
        </>
      }
      onClose={onClose}
      backdropClose
      busy={busy}
      width={520}
      testId="schedule-dialog"
      actions={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
            {t("Cancel")}
          </button>
          <button className="btn btn-primary" onClick={save} disabled={busy || !nameOk || !cron}>
            {t("Save schedule")}
          </button>
        </>
      }
    >
      <div className="dialog-body">
        {t("These {n} steps run on {target} exactly as they ran now. Saving creates a template; it runs only after you approve it with your passkey.", {
          n: p.step_list.length,
          target: p.target,
        })}
      </div>
      <div className="field">
        <label htmlFor="sch-name">{t("Name")}</label>
        <input id="sch-name" className="input mono" placeholder="nightly-dev-rebuild" value={name} onChange={(e) => setName(e.target.value.toLowerCase())} maxLength={63} />
        {name && !nameOk && <div style={{ fontSize: 12, color: "var(--color-danger)", marginTop: 4 }}>{t("Use lowercase letters, numbers and dashes.")}</div>}
      </div>
      <div className="field">
        <label htmlFor="sch-when">{t("When (Europe/Copenhagen)")}</label>
        <select id="sch-when" className="input" value={preset} onChange={(e) => setPreset(e.target.value)}>
          {CRON_PRESETS.map((c) => (
            <option key={c.cron} value={c.cron}>
              {t(c.label)} · {c.cron}
            </option>
          ))}
          <option value="custom">{t("Custom cron…")}</option>
        </select>
        {preset === "custom" && (
          <>
            <input className="input mono" style={{ marginTop: 8 }} aria-label={t("Cron expression")} placeholder="30 2 * * 1-5" value={custom} onChange={(e) => setCustom(e.target.value)} />
            {custom && <div style={{ fontSize: 12, color: "var(--color-neutral-400)", marginTop: 4 }}>{describeCron(custom.trim(), t)}</div>}
          </>
        )}
      </div>
      <div className="field">
        <label>{t("Approval expires after")}</label>
        <Seg name="sch-days" value={days} onChange={setDays} options={(["30", "90", "180"] as const).map((d) => ({ key: d, label: t("{n} days", { n: d }) }))} />
      </div>
      {err && (
        <div role="alert" style={{ fontSize: 13, color: "var(--color-danger)" }}>
          {err}
        </div>
      )}
    </Dialog>
  );
}
