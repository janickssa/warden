"use client";
// Step output (spec 5.10, README 17.3): monospace, ANSI colours, follows the end until you scroll up.
// Output is untrusted text from the target: it is only ever rendered as React text, never as HTML.
import { ArrowDown, Copy, TerminalWindow } from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { useT } from "@/lib/i18n";
import { useToast } from "@/lib/toast";
import { copyText } from "./ui";

const ANSI = /\x1b\[([0-9;]*)m/g; // eslint-disable-line no-control-regex
const FG: Record<number, string> = {
  30: "var(--color-neutral-500)",
  31: "var(--color-danger)",
  32: "var(--color-ok)",
  33: "var(--color-warn)",
  34: "var(--color-accent-300)",
  35: "var(--color-accent-2-300)",
  36: "var(--color-accent-200)",
  37: "var(--color-neutral-100)",
};

export const stripAnsi = (s: string) => s.replace(ANSI, "").replace(/\x1b\[[0-9;?]*[A-Za-z]/g, ""); // eslint-disable-line no-control-regex

function lineColour(line: string): string {
  if (line.startsWith("$ ")) return "var(--color-accent-300)";
  if (/ERR|Error|✘|^exit [1-9]|\^C/.test(line)) return "var(--color-danger)";
  if (/✓|✔|200 OK|0 vulnerabilities/.test(line)) return "var(--color-ok)";
  return "var(--color-neutral-300)";
}

type Span = { text: string; colour?: string; bold?: boolean };

/** SGR colours only; every other escape sequence is dropped. */
function spans(line: string): Span[] {
  const out: Span[] = [];
  let colour: string | undefined;
  let bold = false;
  let last = 0;
  for (const m of line.matchAll(ANSI)) {
    if (m.index! > last) out.push({ text: stripAnsi(line.slice(last, m.index)), colour, bold });
    for (const code of (m[1] || "0").split(";").map(Number)) {
      if (code === 0) (colour = undefined), (bold = false);
      else if (code === 1) bold = true;
      else if (code === 22) bold = false;
      else if (code === 39) colour = undefined;
      else if (FG[code]) colour = FG[code];
      else if (code >= 90 && code <= 97) colour = FG[code - 60];
    }
    last = m.index! + m[0].length;
  }
  if (last < line.length) out.push({ text: stripAnsi(line.slice(last)), colour, bold });
  return out;
}

export function Terminal({ text, live, truncated }: { text: string; live?: boolean; truncated?: boolean }) {
  const t = useT();
  const toast = useToast();
  const body = useRef<HTMLDivElement>(null);
  const [follow, setFollow] = useState(true);
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  if (lines[lines.length - 1] === "") lines.pop();

  useEffect(() => {
    if (follow && body.current) body.current.scrollTop = body.current.scrollHeight;
  }, [text, follow]);

  return (
    <div className="w-term" data-testid="terminal">
      <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "6px 10px", background: "var(--color-surface)", fontSize: 12, color: "var(--color-neutral-400)" }}>
        <TerminalWindow size={14} />
        {t("Output")}
        {live && <span style={{ color: "var(--color-accent)" }}>● {t("live")}</span>}
        <button
          className="btn btn-ghost"
          style={{ fontSize: 12, padding: "1px 6px", marginLeft: "auto" }}
          onClick={() => copyText(stripAnsi(text)).then(() => toast(t("Output copied"), "neutral"))}
        >
          <Copy size={13} /> {t("Copy")}
        </button>
      </div>
      <div
        ref={body}
        className="w-term-body mono"
        style={{ fontSize: 12.5, lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all" }}
        onScroll={(e) => {
          const el = e.currentTarget;
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight <= 8);
        }}
      >
        {lines.map((l, i) => {
          const ss = spans(l);
          const base = ss.some((s) => s.colour) ? "var(--color-neutral-300)" : lineColour(stripAnsi(l));
          return (
            <div key={i} style={{ color: base, minHeight: "1.6em" }}>
              {ss.map((s, j) => (
                <span key={j} style={{ color: s.colour, fontWeight: s.bold ? 600 : undefined }}>
                  {s.text}
                </span>
              ))}
            </div>
          );
        })}
        {truncated && <div style={{ color: "var(--color-warn)" }}>{t("⋯ warden-agent: output truncated · the step kept running, the rest wasn’t kept")}</div>}
      </div>
      {!follow && (
        <button className="btn btn-secondary" style={{ position: "absolute", right: 12, bottom: 10, background: "var(--color-surface)", fontSize: 12 }} onClick={() => setFollow(true)}>
          <ArrowDown size={13} /> {t("Jump to live")}
        </button>
      )}
    </div>
  );
}
