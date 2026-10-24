"use client";
// Live by default (README 17.1): one WebSocket to /ws. Audit notices refetch what they touch; plan output
// streams to whoever watches that plan. Losing the socket (or a failed request) shows the offline banner.
import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";

type Output = { plan_id: string; n: number; seq: number; stream: string; data: string };
type Audit = { seq: number; ts: string; actor: string; action: string; subject: string };
type Ctx = {
  online: boolean;
  lastSeen: number;
  watch: (planId: string, cb: (o: Output) => void) => () => void;
  onAudit: (cb: (a: Audit) => void) => () => void;
  markOffline: () => void;
  retry: () => void;
};

const LiveCtx = createContext<Ctx | null>(null);

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient();
  const [online, setOnline] = useState(true);
  const [lastSeen, setLastSeen] = useState(Date.now());
  const ws = useRef<WebSocket | null>(null);
  const watchers = useRef(new Map<string, Set<(o: Output) => void>>());
  const auditCbs = useRef(new Set<(a: Audit) => void>());
  const backoff = useRef(1000);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pending = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = useCallback(() => {
    if (ws.current && ws.current.readyState <= 1) return;
    const sock = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
    ws.current = sock;
    sock.onopen = () => {
      backoff.current = 1000;
      setOnline(true);
      setLastSeen(Date.now());
      for (const id of watchers.current.keys()) sock.send(JSON.stringify({ watch: id }));
      qc.invalidateQueries();
    };
    sock.onmessage = (ev) => {
      setLastSeen(Date.now());
      const msg = JSON.parse(ev.data);
      if (msg.type === "output") {
        watchers.current.get(msg.plan_id)?.forEach((cb) => cb(msg));
      } else if (msg.type === "audit" || msg.type === "resync") {
        if (msg.type === "audit") auditCbs.current.forEach((cb) => cb(msg));
        if (!pending.current) {
          pending.current = setTimeout(() => {
            pending.current = null;
            qc.invalidateQueries();
          }, 150);
        }
      }
    };
    sock.onclose = (ev) => {
      if (ev.code === 4401) {
        location.assign(`/sign-in?next=${encodeURIComponent(location.pathname + location.search)}&expired=1`);
        return;
      }
      setOnline(false);
      timer.current = setTimeout(connect, backoff.current);
      backoff.current = Math.min(backoff.current * 2, 15000);
    };
  }, [qc]);

  useEffect(() => {
    connect();
    return () => {
      if (timer.current) clearTimeout(timer.current);
      ws.current?.close();
    };
  }, [connect]);

  const watch = useCallback((planId: string, cb: (o: Output) => void) => {
    const set = watchers.current.get(planId) ?? new Set();
    set.add(cb);
    watchers.current.set(planId, set);
    if (ws.current?.readyState === 1) ws.current.send(JSON.stringify({ watch: planId }));
    return () => {
      set.delete(cb);
      if (!set.size) {
        watchers.current.delete(planId);
        if (ws.current?.readyState === 1) ws.current.send(JSON.stringify({ unwatch: planId }));
      }
    };
  }, []);

  const onAudit = useCallback((cb: (a: Audit) => void) => {
    auditCbs.current.add(cb);
    return () => void auditCbs.current.delete(cb);
  }, []);

  const value: Ctx = {
    online,
    lastSeen,
    watch,
    onAudit,
    markOffline: () => setOnline(false),
    retry: () => {
      if (timer.current) clearTimeout(timer.current);
      backoff.current = 1000;
      connect();
      qc.invalidateQueries();
    },
  };
  return <LiveCtx.Provider value={value}>{children}</LiveCtx.Provider>;
}

export function useLive(): Ctx {
  const c = useContext(LiveCtx);
  if (!c) throw new Error("useLive outside LiveProvider");
  return c;
}
