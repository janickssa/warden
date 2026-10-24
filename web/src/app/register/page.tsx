"use client";
// First passkey (or a new device) from the one-time link `warden passkey add NAME` prints. The token is
// single-use and expires in 15 minutes; the name was fixed when the link was made.
import { CheckCircle, Fingerprint, ShieldCheck, XCircle } from "@phosphor-icons/react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import { ApiError, post } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { createCredential, PasskeyCancelled } from "@/lib/webauthn";

function Register() {
  const t = useT();
  const token = useSearchParams().get("token") ?? "";
  const [state, setState] = useState<"idle" | "waiting" | "done" | "error">("idle");
  const [msg, setMsg] = useState("");
  const [name, setName] = useState("");

  const go = async () => {
    setState("waiting");
    try {
      const o = await post<{ challenge_id: string; options: Record<string, unknown> }>("/passkeys/register/options", { token });
      const credential = await createCredential(o.options);
      const r = await post<{ name: string }>("/passkeys/register", { challenge_id: o.challenge_id, credential });
      setName(r.name);
      setState("done");
    } catch (e) {
      setMsg(e instanceof PasskeyCancelled ? t("The passkey prompt was closed or timed out. Nothing was sent.") : e instanceof ApiError ? e.message : (e as Error).message);
      setState("error");
    }
  };

  return (
    <div style={{ minHeight: "100dvh", display: "grid", placeItems: "center", padding: 24, background: "radial-gradient(ellipse at 25% 15%, var(--color-surface), var(--color-bg) 65%)" }}>
      <main style={{ width: "min(400px, 100%)", display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <ShieldCheck size={30} color="var(--color-accent)" />
          <span style={{ fontSize: 24, fontWeight: 500, letterSpacing: "-0.01em" }}>Warden</span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <h2 style={{ fontSize: 26, margin: 0 }}>{t("Register a passkey")}</h2>
          <div style={{ fontSize: 14, lineHeight: 1.5, color: "var(--color-neutral-300)" }}>
            {t("This one-time link adds a passkey to Warden. It signs you in and signs your approvals.")}
          </div>
        </div>
        {!token && (
          <div role="alert" className="w-box w-box--danger">
            {t("This link has no token. Create one with warden passkey add NAME on the Warden guest.")}
          </div>
        )}
        {state === "error" && (
          <div role="alert" className="w-box w-box--danger" style={{ lineHeight: 1.45 }}>
            <XCircle size={18} color="var(--color-danger)" style={{ flex: "none", marginTop: 2 }} />
            <span>{msg}</span>
          </div>
        )}
        {state === "done" ? (
          <>
            <div role="status" className="w-box w-box--accent" style={{ lineHeight: 1.45 }}>
              <CheckCircle size={18} color="var(--color-ok)" style={{ flex: "none", marginTop: 2 }} />
              <span>{t("Passkey “{name}” registered.", { name })}</span>
            </div>
            <Link className="btn btn-primary btn-block" style={{ minHeight: 48, justifyContent: "center" }} href="/sign-in">
              {t("Sign in")}
            </Link>
          </>
        ) : (
          <button className="btn btn-primary btn-block" style={{ minHeight: 48, fontSize: 15, justifyContent: "center" }} onClick={go} disabled={!token || state === "waiting"}>
            <Fingerprint size={18} /> {state === "waiting" ? t("Waiting for passkey…") : t("Create passkey")}
          </button>
        )}
      </main>
    </div>
  );
}

export default function Page() {
  return (
    <Suspense>
      <Register />
    </Suspense>
  );
}
