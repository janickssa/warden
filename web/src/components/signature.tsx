"use client";
// Offline signature upload (spec 15.4). Loosening never goes out on Warden's own key: the pending bundle
// is downloaded, signed with warden-sign on the machine with the offline key, and the signature uploaded.
import { FileArrowUp } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { ApiError, post } from "@/lib/api";
import { fmtBytes } from "@/lib/format";
import { useT } from "@/lib/i18n";
import { useToast } from "@/lib/toast";
import type { PublishResult } from "@/lib/types";
import { Dialog } from "./dialog";
import { copyText } from "./ui";

export function SignatureDialog({ mode, version, onClose }: { mode: "bundle" | "lift"; version: number; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const [file, setFile] = useState<{ name: string; size: number; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const command = `warden-sign sign bundle-v${version}.json --key offline.key`;

  const verify = async () => {
    if (!file) return;
    setBusy(true);
    setErr(null);
    try {
      const r = await post<PublishResult>("/policy/pending/signature", { content: file.text });
      toast(mode === "lift" ? t("Lockdown lifted · v{v} rolling out", { v: r.version }) : t("Offline signature verified · v{v} rolling out", { v: r.version }));
      qc.invalidateQueries();
      onClose();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog
      title={mode === "lift" ? t("Lift lockdown") : t("Upload offline signature · v{v}", { v: version })}
      onClose={onClose}
      busy={busy}
      width={520}
      testId="signature-dialog"
      actions={
        <>
          <button className="btn btn-secondary" onClick={onClose} disabled={busy}>
            {t("Cancel")}
          </button>
          <button className="btn btn-primary" onClick={verify} disabled={!file || busy}>
            {busy ? t("Verifying…") : mode === "lift" ? t("Verify & lift lockdown") : t("Verify & publish")}
          </button>
        </>
      }
    >
      <div className="dialog-body" style={{ textWrap: "pretty" }}>
        {mode === "lift"
          ? t("Lifting restores the rules from before lockdown as policy v{v}. That counts as loosening, so it needs the offline key.", { v: version })
          : t("Warden can’t sign loosening changes on its own. Sign the bundle with the offline key, then upload the signature.")}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>
          {t("1 · On the machine with the offline key")}{" "}
          <a href="/api/policy/pending/file" download={`bundle-v${version}.json`}>
            {t("Download bundle-v{v}.json", { v: version })}
          </a>
        </div>
        <div className="mono" style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 10px", borderRadius: "var(--radius-md)", background: "var(--color-bg)", fontSize: 13 }}>
          <span style={{ flex: 1, wordBreak: "break-all" }}>{command}</span>
          <button className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => copyText(command).then(() => toast(t("Command copied"), "neutral"))}>
            {t("Copy")}
          </button>
        </div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ fontSize: 12, color: "var(--color-neutral-400)" }}>{t("2 · Upload the signature file")}</div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 12px", border: "1px dashed var(--color-divider)", borderRadius: "var(--radius-md)", fontSize: 13 }}>
          <FileArrowUp size={20} color="var(--color-neutral-400)" />
          <span className="mono" style={{ flex: 1, color: file ? "var(--color-neutral-100)" : "var(--color-neutral-500)", wordBreak: "break-all" }}>
            {file ? `${file.name} · ${fmtBytes(file.size)}` : t("No file chosen")}
          </span>
          <button className="btn btn-secondary" style={{ fontSize: 13 }} onClick={() => input.current?.click()} disabled={busy}>
            {t("Choose file…")}
          </button>
          <input
            ref={input}
            type="file"
            accept=".json,.sig,application/json"
            hidden
            data-testid="signature-file"
            onChange={async (e) => {
              const f = e.target.files?.[0];
              if (f) setFile({ name: f.name, size: f.size, text: await f.text() });
            }}
          />
        </div>
      </div>
      {busy && <div style={{ fontSize: 13, color: "var(--color-accent-300)" }}>{t("◌ Verifying the ed25519 signature against the offline public key…")}</div>}
      {err && (
        <div role="alert" className="w-box w-box--danger" style={{ fontSize: 13 }}>
          {err}
        </div>
      )}
    </Dialog>
  );
}
