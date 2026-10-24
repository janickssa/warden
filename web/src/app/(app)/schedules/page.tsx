"use client";
// Schedules (spec 7). Approved-once plan templates arrive in M7; until then the page says so.
import { ClockClockwise } from "@phosphor-icons/react";
import { useQuery } from "@tanstack/react-query";
import { Empty, Header, Page, Skeleton } from "@/components/ui";
import { api } from "@/lib/api";
import { useT } from "@/lib/i18n";

export default function Schedules() {
  const t = useT();
  const q = useQuery({ queryKey: ["schedules"], queryFn: () => api<Record<string, string>[]>("/schedules") });
  return (
    <Page max={1040}>
      <Header title={t("Schedules")} sub={t("Plan templates you approved once. Any change needs a new approval. Times are Europe/Copenhagen.")} />
      {q.isPending ? (
        <Skeleton height={44} gap={8} />
      ) : (
        <Empty
          icon={<ClockClockwise size={28} color="var(--color-neutral-500)" />}
          title={t("No schedules yet")}
          text={t("Claude can propose a plan as a schedule once scheduling arrives. Each one needs its own approval.")}
        />
      )}
    </Page>
  );
}
