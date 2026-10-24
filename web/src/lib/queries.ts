"use client";
// Shared queries. The socket's audit notices invalidate everything (live.tsx), so pages never poll.
import { useQuery } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";
import { api, Offline } from "./api";
import { useLive } from "./live";
import type { AgentList, Me, PlanDetail, PlanList, StatusView } from "./types";

export const useMe = () => useQuery({ queryKey: ["me"], queryFn: () => api<Me>("/auth/me"), retry: false, staleTime: 60_000 });
export const useStatus = () => useQuery({ queryKey: ["status"], queryFn: () => api<StatusView>("/status") });
export const usePlans = () => useQuery({ queryKey: ["plans"], queryFn: () => api<PlanList>("/plans") });
export const useApprovals = () => useQuery({ queryKey: ["approvals"], queryFn: () => api<PlanList>("/approvals") });
export const usePlan = (id: string | undefined) =>
  useQuery({ queryKey: ["plan", id], queryFn: () => api<PlanDetail>(`/plans/${encodeURIComponent(id!)}`), enabled: !!id });
export const useAgents = () => useQuery({ queryKey: ["agents"], queryFn: () => api<AgentList>("/agents") });

/** Offline when the socket is down or the last status fetch couldn't reach Warden. */
export function useOffline(): boolean {
  const live = useLive();
  const s = useStatus();
  return !live.online || s.error instanceof Offline;
}

const subscribe = (cb: () => void) => {
  const m = window.matchMedia("(max-width: 767px)");
  m.addEventListener("change", cb);
  return () => m.removeEventListener("change", cb);
};
/** Below 768 px the dashboard is a single column with Approvals and Plan detail only (README 17.3). */
export const usePhone = () =>
  useSyncExternalStore(subscribe, () => window.matchMedia("(max-width: 767px)").matches, () => false);
