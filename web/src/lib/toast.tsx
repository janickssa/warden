"use client";
import { CheckCircle, Info, XCircle } from "@phosphor-icons/react";
import { createContext, useCallback, useContext, useRef, useState } from "react";

type Kind = "ok" | "bad" | "neutral";
const ToastCtx = createContext<(text: string, kind?: Kind) => void>(() => {});

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toast, setToast] = useState<{ text: string; kind: Kind; id: number } | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const show = useCallback((text: string, kind: Kind = "ok") => {
    if (timer.current) clearTimeout(timer.current);
    setToast({ text, kind, id: Date.now() });
    timer.current = setTimeout(() => setToast(null), 3600);
  }, []);
  return (
    <ToastCtx.Provider value={show}>
      {children}
      {toast && (
        <div
          role="status"
          className="card elev-md"
          style={{ position: "fixed", right: 24, bottom: 24, flexDirection: "row", alignItems: "center", gap: 10, padding: "10px 14px", fontSize: 14, maxWidth: 420, zIndex: 70 }}
        >
          {toast.kind === "ok" && <CheckCircle size={17} color="var(--color-ok)" />}
          {toast.kind === "bad" && <XCircle size={17} color="var(--color-danger)" />}
          {toast.kind === "neutral" && <Info size={17} color="var(--color-neutral-500)" />}
          <span>{toast.text}</span>
        </div>
      )}
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);
