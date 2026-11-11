import Foundation

public enum Tone: Sendable { case ok, warn, danger, accent, neutral }

/// Status badges (spec 0.3), shared with the web dashboard's wording.
public enum Badge {
    static let table: [String: (String, Tone)] = [
        "low": ("● Low risk", .ok), "medium": ("▲ Medium risk", .warn), "high": ("■ High risk", .danger),
        "allow": ("✓ Allow", .ok), "escalate": ("▲ Escalate", .warn), "deny": ("✕ Deny", .danger),
        "awaiting_approval": ("⏸ Awaiting", .warn), "approved": ("✓ Approved", .accent), "running": ("◌ Running", .accent),
        "succeeded": ("✓ Succeeded", .ok), "failed": ("✕ Failed", .danger), "refused": ("✕ Refused", .danger),
        "rejected": ("✕ Rejected", .neutral), "cancelled": ("— Cancelled", .neutral), "expired": ("— Expired", .neutral),
        "skipped": ("— Skipped", .neutral), "pending": ("· Pending", .neutral), "reviewing": ("◌ Re-reviewing", .accent),
        "invalidated": ("⊘ Invalidated", .warn), "held": ("⏸ Held", .warn),
    ]

    public static func of(_ key: String, _ l: L = L()) -> (String, Tone) {
        let (label, tone) = table[key] ?? (key, .neutral)
        return (l.t(label), tone)
    }

    /// Approved-but-held reads as held.
    public static func planKey(status: String, heldReason: String?) -> String {
        status == "approved" && heldReason != nil ? "held" : status
    }
}

public enum PlanLogic {
    static let strictness: [Verdict: Int] = [.allow: 0, .escalate: 1, .deny: 2]

    /// Strictest verdict wins; an unavailable reviewer counts as escalate, and no reviewer at all is
    /// escalate (README 9, DECISIONS M5-05). Bug 3: the iPhone shows this exactly like the web.
    public static func finalVerdict(_ reviewers: [Reviewer]) -> Verdict {
        guard !reviewers.isEmpty else { return .escalate }
        return reviewers.map { $0.unavailable ? .escalate : $0.verdict }.max { strictness[$0]! < strictness[$1]! }!
    }

    /// What the app shows: never less strict than Warden's own final verdict.
    public static func shownFinal(_ plan: PlanDetail) -> Verdict {
        let mine = finalVerdict(plan.reviewers)
        return strictness[mine]! >= strictness[plan.finalVerdict]! ? mine : plan.finalVerdict
    }

    public static func reviewerLine(_ r: Reviewer, _ l: L = L()) -> (String, Tone) {
        r.unavailable ? (l.t("○ Unavailable · counted as escalate"), .warn) : Badge.of(r.verdict.rawValue, l)
    }

    public static func isPending(_ status: String) -> Bool { status == "awaiting_approval" || status == "reviewing" }

    public static func isExpired(_ plan: PlanDetail, now: Date) -> Bool {
        guard plan.status == "awaiting_approval", let exp = Format.parse(plan.expiresAt) else { return false }
        return exp <= now
    }

    /// README 17.4: high-risk plans must be reviewed in the app, never from a notification.
    public static func canApproveFromNotification(risk: Risk?) -> Bool { risk != .high }

    /// README 17.4: high-risk plans also need you to scroll through all steps first.
    public static func needsScrollGate(_ plan: PlanDetail) -> Bool { plan.risk == .high }

    /// Spec 5.11: why the target's agent can't run it yet, in which tone.
    public static func agentWarning(target: String, agent: AgentState?, _ l: L = L()) -> (String, Tone)? {
        guard let a = agent else { return nil }
        switch a.state {
        case "lockdown":
            return (l.t("Lockdown active. You can review and approve this plan; nothing state-changing runs until lockdown is lifted."), .danger)
        case "offline":
            return (l.t("{target}’s agent is offline. You can review and approve; it runs when the agent reconnects and is on policy v{v}.", ["target": target, "v": a.latestVersion ?? 0]), .danger)
        case "behind":
            return (l.t("{target}’s agent is on policy v{have}, latest is v{v}. You can review and approve; the dispatcher holds it until the agent is current.", ["target": target, "have": a.policyVersion ?? 0, "v": a.latestVersion ?? 0]), .warn)
        case "revoked":
            return (l.t("{target}’s agent was revoked. Enroll a new agent before this can run.", ["target": target]), .danger)
        case "missing":
            return (l.t("No agent is enrolled for {target} yet.", ["target": target]), .danger)
        default:
            return nil
        }
    }

    /// The info line for a plan that isn't waiting (spec 5.7).
    public static func info(_ p: PlanDetail, now: Date, _ l: L = L()) -> (String, Tone)? {
        let at = p.approval.flatMap { Format.parse($0.at) }.map(Format.time) ?? ""
        if isExpired(p, now: now) || p.status == "expired" {
            return (l.t("Expired at {time}. Ask Claude to propose again.", ["time": Format.parse(p.expiresAt).map(Format.time) ?? ""]), .neutral)
        }
        switch p.status {
        case "reviewing": return (l.t("◌ Re-reviewing your edits · policy, then gatekeepers"), .accent)
        case "held": return (l.t("⏸ Approved {time} · held. It runs as soon as it can.", ["time": at]), .warn)
        case "approved":
            return p.heldReason != nil ? (l.t("⏸ Approved {time} · held. It runs as soon as it can.", ["time": at]), .warn)
                : (l.t("✓ Approved {time} · waiting for Claude to call execute_plan", ["time": at]), .accent)
        case "running": return (l.t("◌ Running"), .accent)
        case "succeeded": return (l.t("✓ Succeeded"), .ok)
        case "failed": return (l.t("✕ Failed at step {n}. Claude must propose a revision.", ["n": p.failedAt ?? 0]), .danger)
        case "invalidated": return (l.t("⊘ Invalidated by a newer policy. Claude must propose a new plan."), .warn)
        case "cancelled": return (l.t("— Cancelled by kill switch. Claude must propose a new plan."), .neutral)
        case "rejected": return (p.rejectReason.map { l.t("Rejected · “{reason}”", ["reason": $0]) } ?? l.t("Rejected"), .neutral)
        default: return nil
        }
    }
}
