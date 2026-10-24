"use client";
// Everything behind sign-in. The session cookie is httpOnly, so "signed in" means /api/auth/me answers;
// a 401 anywhere sends the browser to /sign-in with the page to come back to.
import { WifiSlash } from "@phosphor-icons/react";
import { Suspense } from "react";
import { ApiError } from "@/lib/api";
import { PasskeyProvider } from "@/components/passkey";
import { Shell } from "@/components/shell";
import { I18nProvider } from "@/lib/i18n";
import { LiveProvider } from "@/lib/live";
import { useMe, useStatus } from "@/lib/queries";

function Language({ children }: { children: React.ReactNode }) {
  const status = useStatus();
  return <I18nProvider lang={status.data?.language === "da" ? "da" : "en"}>{children}</I18nProvider>;
}

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const me = useMe();
  if (me.error && !me.data && !(me.error instanceof ApiError)) {
    return (
      <div role="alert" className="w-box w-box--warn" style={{ margin: 24 }}>
        <WifiSlash size={18} color="var(--color-warn)" />
        <span style={{ flex: 1 }}>Can’t reach Warden. Is WireGuard connected?</span>
        <button className="btn btn-secondary" style={{ fontSize: 13 }} onClick={() => me.refetch()}>
          Retry
        </button>
      </div>
    );
  }
  if (!me.data) return null;
  return (
    <LiveProvider>
      <Language>
        <PasskeyProvider>
          <Suspense>
            <Shell>{children}</Shell>
          </Suspense>
        </PasskeyProvider>
      </Language>
    </LiveProvider>
  );
}
