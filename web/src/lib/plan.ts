// Plan helpers shared by Approvals, Plans and Plan detail. Texts are built here (not taken from the
// API's English warning) so they translate.
import type { T } from "./i18n";
import type { PlanSummary } from "./types";

export const PENDING = ["awaiting_approval", "reviewing"];
export const isPending = (s: string) => PENDING.includes(s);

type Agent = NonNullable<PlanSummary["agent"]>;

/** Spec 5.11: why the target's agent can't run this yet, and in which colour. */
export function agentWarn(target: string, a: Agent | null | undefined, t: T): { text: string; colour: "warn" | "danger" } | null {
  if (!a) return null;
  switch (a.state) {
    case "lockdown":
      return { text: t("Lockdown active. You can review and approve this plan; nothing state-changing runs until lockdown is lifted."), colour: "danger" };
    case "offline":
      return { text: t("{target}’s agent is offline. You can review and approve; it runs when the agent reconnects and is on policy v{v}.", { target, v: a.latest_version }), colour: "danger" };
    case "behind":
      return {
        text: t("{target}’s agent is on policy v{have}, latest is v{v}. You can review and approve; the dispatcher holds it until the agent is current.", {
          target,
          have: a.policy_version ?? 0,
          v: a.latest_version,
        }),
        colour: "warn",
      };
    case "revoked":
      return { text: t("{target}’s agent was revoked. Enroll a new agent before this can run.", { target }), colour: "danger" };
    case "missing":
      return { text: t("No agent is enrolled for {target} yet.", { target }), colour: "danger" };
    default:
      return null;
  }
}

/** `sha256:8f3e1c2…a1d0`: the first 11 characters, an ellipsis, the last 4 (spec 5.8). */
export const shortHash = (h: string) => (h.length > 20 ? `${h.slice(0, 11)}…${h.slice(-4)}` : h);
