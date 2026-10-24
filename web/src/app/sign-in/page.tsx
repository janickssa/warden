"use client";
// Sign-in (spec 2): passkey only, no password. After success, back to the page the session expired on.
import { ClockCountdown, Fingerprint, LockKey, ShieldCheck, WifiSlash, XCircle } from "@phosphor-icons/react";
import { useQueryClient } from "@tanstack/react-query";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useRef, useState } from "react";
import { ApiError, Offline, post } from "@/lib/api";
import { N, useT } from "@/lib/i18n";
import { useToast } from "@/lib/toast";
import { getAssertion, PasskeyCancelled } from "@/lib/webauthn";

const LABELS: Record<string, string> = {
  approvals: N("Approvals"),
  plans: N("Plans"),
  feed: N("Live feed"),
  schedules: N("Schedules"),
  agents: N("Agents"),
  groups: N("Groups"),
  policy: N("Policy"),
  audit: N("Audit log"),
  settings: N("Settings"),
};

/** Only same-site paths are followed after sign-in; anything else goes to Approvals. */
function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") ? next : "/approvals";
}

function pageLabel(path: string): string {
  if (/^\/plans\/[^/]+/.test(path)) return N("the plan you had open");
  return LABELS[path.split(/[/?]/)[1] ?? ""] ?? N("Approvals");
}

function SignIn() {
  const t = useT();
  const toast = useToast();
  const router = useRouter();
  const qc = useQueryClient();
  const params = useSearchParams();
  const next = safeNext(params.get("next"));
  const expired = params.get("expired") === "1";
  const [state, setState] = useState<"idle" | "waiting" | "cancelled" | "unknown" | "error">("idle");
  const [offline, setOffline] = useState(false);
  const [msg, setMsg] = useState("");
  const abort = useRef<AbortController | null>(null);
  const label = pageLabel(next);

  const signIn = async () => {
    setState("waiting");
    setOffline(false);
    abort.current = new AbortController();
    try {
      const o = await post<{ challenge_id: string; options: Record<string, unknown> }>("/auth/options");
      const credential = await getAssertion(o.options, abort.current.signal);
      await post("/auth/login", { challenge_id: o.challenge_id, credential });
      qc.clear();
      toast(t("Signed in · back on {page}", { page: label === "the plan you had open" ? t("the plan") : t(label) }));
      router.replace(next);
    } catch (e) {
      if (e instanceof PasskeyCancelled) setState("cancelled");
      else if (e instanceof Offline) {
        setOffline(true);
        setState("idle");
      } else if (e instanceof ApiError && e.code === "unknown_passkey") setState("unknown");
      else {
        setMsg((e as Error).message);
        setState("error");
      }
    }
  };

  const failed = state === "cancelled" || state === "unknown" || state === "error";
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 60,
        display: "grid",
        placeItems: "center",
        padding: 24,
        overflow: "auto",
        background: "radial-gradient(ellipse at 25% 15%, var(--color-surface), var(--color-bg) 65%)",
      }}
    >
      <main style={{ width: "min(400px, 100%)", display: "flex", flexDirection: "column", gap: "var(--space-6)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <ShieldCheck size={30} color="var(--color-accent)" />
          <span style={{ fontSize: 24, fontWeight: 500, letterSpacing: "-0.01em" }}>Warden</span>
        </div>
        {expired && (
          <div className="w-box w-box--warn" style={{ lineHeight: 1.45 }}>
            <ClockCountdown size={18} color="var(--color-warn)" style={{ flex: "none", marginTop: 2 }} />
            <span>{t("Your session expired. Sign in again to go back to {page}.", { page: t(label) })}</span>
          </div>
        )}
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <h2 style={{ fontSize: 26, margin: 0 }}>{t("Sign in")}</h2>
          <div style={{ fontSize: 14, lineHeight: 1.5, color: "var(--color-neutral-300)" }}>
            {t("Use a passkey you registered with Warden. There is no password login.")}
          </div>
        </div>
        {offline && (
          <div role="alert" className="w-box w-box--warn">
            <WifiSlash size={18} color="var(--color-warn)" style={{ flex: "none" }} />
            <span>{t("Can’t reach Warden. Is WireGuard connected?")}</span>
          </div>
        )}
        {failed && (
          <div role="alert" className="w-box w-box--danger" style={{ lineHeight: 1.45 }}>
            <XCircle size={18} color="var(--color-danger)" style={{ flex: "none", marginTop: 2 }} />
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              <span style={{ color: "var(--color-danger)" }}>
                {state === "cancelled" ? t("Sign-in cancelled") : state === "unknown" ? t("This passkey isn’t registered with Warden") : t("Sign-in failed")}
              </span>
              <span style={{ color: "var(--color-neutral-200)" }}>
                {state === "cancelled"
                  ? t("The passkey prompt was closed or timed out. Nothing was sent.")
                  : state === "unknown"
                    ? t("Pick a passkey you registered under Settings → Passkeys & sessions, or use your backup YubiKey.")
                    : msg}
              </span>
            </div>
          </div>
        )}
        <button className="btn btn-primary btn-block" style={{ minHeight: 48, fontSize: 15, justifyContent: "center" }} onClick={signIn} disabled={state === "waiting"}>
          {state === "waiting" ? (
            <>
              <span className="w-spin" style={{ display: "inline-flex" }}>◌</span> {t("Waiting for passkey…")}
            </>
          ) : (
            <>
              <Fingerprint size={18} /> {failed ? t("Try again") : t("Sign in with passkey")}
            </>
          )}
        </button>
        {state === "waiting" && (
          <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13, color: "var(--color-accent-300)" }}>
            <span style={{ flex: 1 }}>{t("◌ Follow your browser’s passkey prompt…")}</span>
            <button
              className="btn btn-ghost"
              style={{ fontSize: 13 }}
              onClick={() => {
                abort.current?.abort();
                setState("cancelled");
              }}
            >
              {t("Cancel")}
            </button>
          </div>
        )}
        <div style={{ display: "flex", gap: 8, fontSize: 12, lineHeight: 1.5, color: "var(--color-neutral-500)" }}>
          <LockKey size={15} style={{ flex: "none", marginTop: 2 }} />
          <span>{t("The dashboard is only reachable over WireGuard. Sessions last 12 hours.")}</span>
        </div>
      </main>
    </div>
  );
}

export default function Page() {
  return (
    <Suspense>
      <SignIn />
    </Suspense>
  );
}
