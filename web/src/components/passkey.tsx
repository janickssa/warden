"use client";
// The passkey prompt (spec 15.1). Every confirmation goes through it: Warden issues a challenge bound to
// one purpose and subject, the browser signs it, and the signed assertion goes back with the action.
import { Fingerprint } from "@phosphor-icons/react";
import { createContext, useCallback, useContext, useRef, useState } from "react";
import { ApiError, post } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { getAssertion, PasskeyCancelled } from "@/lib/webauthn";
import { Dialog } from "./dialog";

export type Signed = { challenge_id: string; credential: Record<string, unknown> };
type Opts = { challenge_id: string; options: Record<string, unknown> };
export type PasskeyRequest<R> = {
  title?: string;
  body: React.ReactNode;
  options: () => Promise<Opts>;
  submit: (signed: Signed) => Promise<R>;
};
type Ask = <R>(req: PasskeyRequest<R>) => Promise<R>;

const Ctx = createContext<Ask | null>(null);

export const confirmOptions = (purpose: string, subject = "") => post<Opts>("/confirm/options", { purpose, subject });

export function PasskeyProvider({ children }: { children: React.ReactNode }) {
  const t = useT();
  const [req, setReq] = useState<PasskeyRequest<unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const settle = useRef<{ ok: (v: unknown) => void; fail: (e: unknown) => void } | null>(null);

  const ask = useCallback<Ask>(
    (r) =>
      new Promise((ok, fail) => {
        settle.current = { ok: ok as (v: unknown) => void, fail };
        setErr(null);
        setBusy(false);
        setReq(r as PasskeyRequest<unknown>);
      }),
    [],
  );

  const cancel = () => {
    if (busy) return;
    settle.current?.fail(new PasskeyCancelled("cancelled"));
    settle.current = null;
    setReq(null);
  };

  const go = async () => {
    if (!req) return;
    setBusy(true);
    setErr(null);
    try {
      const o = await req.options();
      const credential = await getAssertion(o.options);
      const out = await req.submit({ challenge_id: o.challenge_id, credential });
      settle.current?.ok(out);
      settle.current = null;
      setReq(null);
    } catch (e) {
      if (e instanceof PasskeyCancelled) setErr(t("The passkey prompt was closed or timed out. Nothing was sent."));
      else if (e instanceof ApiError) {
        // A refusal from Warden ends the request: the caller shows it where it belongs.
        settle.current?.fail(e);
        settle.current = null;
        setReq(null);
      } else setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Ctx.Provider value={ask}>
      {children}
      {req && (
        <Dialog title={req.title ?? t("Confirm with your passkey")} onClose={cancel} busy={busy} testId="passkey-dialog"
          actions={
            <>
              <button className="btn btn-secondary" onClick={cancel} disabled={busy}>
                {t("Cancel")}
              </button>
              <button className="btn btn-primary" onClick={go} disabled={busy}>
                {busy ? t("Waiting for passkey…") : t("Use passkey")}
              </button>
            </>
          }
        >
          <div className="dialog-body" style={{ textWrap: "pretty" }}>
            {req.body}
          </div>
          <div style={{ display: "flex", justifyContent: "center", padding: "12px 0" }}>
            <Fingerprint size={56} color={busy ? "var(--color-accent)" : "var(--color-neutral-400)"} />
          </div>
          {err && (
            <div role="alert" style={{ fontSize: 13, color: "var(--color-warn)" }}>
              {err}
            </div>
          )}
        </Dialog>
      )}
    </Ctx.Provider>
  );
}

export function usePasskey(): Ask {
  const c = useContext(Ctx);
  if (!c) throw new Error("usePasskey outside PasskeyProvider");
  return c;
}

export const isCancel = (e: unknown) => e instanceof PasskeyCancelled;
