"use client";
// Dialogs (spec 1.6): Esc closes the top one unless it is busy; some close on a backdrop click, and the
// passkey, signature and Add agent dialogs never do. Keyboard shortcuts check `anyDialogOpen()`.
import { useEffect, useId, useRef } from "react";

const stack: string[] = [];
export const anyDialogOpen = () => stack.length > 0;

export function Dialog({
  title,
  onClose,
  backdropClose = false,
  busy = false,
  width,
  children,
  actions,
  testId,
}: {
  title: React.ReactNode;
  onClose: () => void;
  backdropClose?: boolean;
  busy?: boolean;
  width?: number;
  children?: React.ReactNode;
  actions?: React.ReactNode;
  testId?: string;
}) {
  const id = useId();
  const ref = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  const isBusy = useRef(busy);
  close.current = onClose;
  isBusy.current = busy;

  useEffect(() => {
    stack.push(id);
    const prev = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>("textarea, input, button.btn-primary, button");
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && stack[stack.length - 1] === id && !isBusy.current) {
        e.preventDefault();
        close.current();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      stack.splice(stack.indexOf(id), 1);
      prev?.focus?.();
    };
  }, [id]);

  return (
    <div
      className="dialog-backdrop"
      style={{ zIndex: 40 }}
      onMouseDown={(e) => {
        if (backdropClose && !busy && e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={ref}
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${id}-t`}
        data-testid={testId}
        style={width ? { width: `min(${width}px, 100%)` } : undefined}
      >
        <div className="dialog-title" id={`${id}-t`} style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {title}
        </div>
        {children}
        {actions && <div className="dialog-actions">{actions}</div>}
      </div>
    </div>
  );
}
