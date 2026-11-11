import SwiftUI
import WardenCore

extension Tone {
    public var color: Color {
        switch self {
        case .ok: Theme.ok
        case .warn: Theme.warn
        case .danger: Theme.danger
        case .accent: Theme.accent300
        case .neutral: Theme.neutral500
        }
    }
}

/// A status badge (spec 0.3): tinted fill, coloured border and text.
public struct BadgeView: View {
    let text: String
    let tone: Tone

    public init(_ key: String, l: L) {
        let b = Badge.of(key, l)
        text = b.0
        tone = b.1
    }

    public init(text: String, tone: Tone) {
        self.text = text
        self.tone = tone
    }

    public var body: some View {
        Text(text)
            .font(.caption)
            .padding(.horizontal, 8)
            .padding(.vertical, 2)
            .foregroundStyle(tone.color)
            .background(tone.color.opacity(0.15), in: RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(tone.color.opacity(0.4)))
    }
}

/// Verdicts, strictest wins; an unavailable reviewer reads as escalate (bug 3, spec 5.3).
public struct VerdictsView: View {
    let plan: PlanDetail
    let l: L

    public init(plan: PlanDetail, l: L) {
        self.plan = plan
        self.l = l
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(l.t("Verdicts")).font(.caption.weight(.semibold)).textCase(.uppercase).foregroundStyle(Theme.neutral400)
                if plan.reviewersDisagree {
                    Text(l.t("▲ Reviewers disagree")).font(.caption).foregroundStyle(Theme.warn)
                }
                Spacer()
                let final = Badge.of(PlanLogic.shownFinal(plan).rawValue, l)
                Text(final.0).font(.caption).foregroundStyle(final.1.color)
            }
            row(name: l.t("Policy"), model: nil,
                verdict: plan.policyOk ? (l.t("✓ Passed"), Tone.ok) : (l.t("✕ Denied"), Tone.danger),
                summary: plan.policyOk ? l.t("Passed · every command matched the allowlist") : plan.violations.map(\.message).joined(separator: " · "),
                highlight: false)
            ForEach(plan.reviewers, id: \.name) { r in
                row(name: r.name, model: r.model, verdict: PlanLogic.reviewerLine(r, l), summary: r.summary,
                    highlight: r.unavailable || (plan.reviewersDisagree && r.verdict != .allow))
            }
        }
        .padding(14)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 8))
    }

    func row(name: String, model: String?, verdict: (String, Tone), summary: String, highlight: Bool) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(alignment: .firstTextBaseline) {
                Text(name).font(.subheadline)
                if let model { Text(model).font(.caption2.monospaced()).foregroundStyle(Theme.neutral500) }
                Spacer()
                Text(verdict.0).font(.caption).foregroundStyle(verdict.1.color)
            }
            if !summary.isEmpty {
                Text(summary).font(.footnote).foregroundStyle(Theme.neutral300)
            }
        }
        .padding(8)
        .background(highlight ? Theme.warn.opacity(0.08) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
    }
}

/// Every command in full, SF Mono, wrapping (README 17.4).
public struct StepsView: View {
    let steps: [StepView]
    let l: L
    let notes: [Int: [(String, String)]]

    public init(plan: PlanDetail, l: L) {
        steps = plan.stepList
        self.l = l
        var n: [Int: [(String, String)]] = [:]
        for r in plan.reviewers {
            for (k, v) in r.notes ?? [:] where !v.isEmpty { n[Int(k) ?? 0, default: []].append((r.name, v)) }
        }
        notes = n
    }

    public init(steps: [StepView], l: L) {
        self.steps = steps
        self.l = l
        notes = [:]
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            ForEach(steps) { s in
                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text("\(s.n)").font(.footnote.monospacedDigit()).foregroundStyle(Theme.neutral400)
                            .frame(width: 22, height: 22).overlay(Circle().stroke(Theme.neutral600))
                        Text(s.purpose).font(.subheadline)
                        Text(s.kind).font(.caption2.monospaced()).padding(.horizontal, 6).background(Theme.neutral800, in: Capsule())
                        Spacer()
                        if let st = s.status, st != "pending" {
                            let badge = Badge.of(st, l)
                            Text(badge.0 + (s.durationS.map { " · " + Format.duration($0) } ?? "")).font(.caption).foregroundStyle(badge.1.color)
                        }
                    }
                    Text(s.command)
                        .font(.system(.footnote, design: .monospaced))
                        .foregroundStyle(Theme.neutral100)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(10)
                        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 8))
                    Text("cwd \(s.cwd) · \(l.t("timeout")) \(Format.duration(Double(s.timeoutS))) · \(l.t("expects exit")) \(s.expectExit)")
                        .font(.caption2).foregroundStyle(Theme.neutral500)
                    ForEach(Array((notes[s.n] ?? []).enumerated()), id: \.offset) { _, note in
                        Text("▲ \(note.0) \(note.1)").font(.caption).foregroundStyle(Theme.neutral200)
                            .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                            .background(Theme.warn.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
        }
    }
}

/// Header: goal, badges, target and ID (spec 5.1).
public struct PlanHeaderView: View {
    let plan: PlanDetail
    let l: L

    public init(plan: PlanDetail, l: L) {
        self.plan = plan
        self.l = l
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(plan.goal).font(.title3.weight(.semibold))
            HStack(spacing: 6) {
                BadgeView(Badge.planKey(status: plan.status, heldReason: plan.heldReason), l: l)
                if let r = plan.risk { BadgeView(r.rawValue, l: l) }
                Text(plan.target).font(.footnote).foregroundStyle(Theme.neutral200)
            }
            Text("\(plan.id) · \(plan.requestedBy)").font(.caption2.monospaced()).foregroundStyle(Theme.neutral500)
            if let warning = PlanLogic.agentWarning(target: plan.target, agent: plan.agent, l) {
                Label(warning.0, systemImage: "exclamationmark.triangle").font(.footnote).foregroundStyle(warning.1.color)
                    .padding(10).background(warning.1.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }
}
