import SwiftUI
import WardenCore
import WardenKit

/// Approvals (spec 3): waiting plans oldest first, then recently decided.
struct ApprovalsView: View {
    @EnvironmentObject var model: AppModel

    var pending: [PlanSummary] { model.approvals.filter { PlanLogic.isPending($0.status) } }
    var decided: [PlanSummary] { model.approvals.filter { !PlanLogic.isPending($0.status) } }

    var body: some View {
        NavigationStack(path: $model.planPath) {
            List {
                if pending.isEmpty {
                    VStack(spacing: 6) {
                        Image(systemName: "checkmark.circle").font(.title).foregroundStyle(Theme.neutral500)
                        Text(model.l.t("No plans waiting")).font(.headline)
                        Text(model.l.t("Claude hasn’t asked for anything.")).font(.subheadline).foregroundStyle(Theme.neutral400)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 30)
                    .listRowBackground(Color.clear)
                }
                ForEach(pending) { p in
                    NavigationLink(value: p.id) { PlanRow(plan: p) }
                }
                if !decided.isEmpty {
                    Section(model.l.t("Recently decided")) {
                        ForEach(decided) { p in
                            NavigationLink(value: p.id) {
                                HStack {
                                    let b = Badge.of(Badge.planKey(status: p.status, heldReason: p.heldReason), model.l)
                                    Text(b.0).font(.caption).foregroundStyle(b.1.color).frame(width: 96, alignment: .leading)
                                    Text(p.goal).font(.subheadline).lineLimit(2)
                                }
                            }
                        }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg)
            .navigationTitle(model.l.t("Approvals"))
            .refreshable { await model.refresh() }
            .navigationDestination(for: String.self) { id in
                if id.hasPrefix("sch_") { ScheduleDetailView(id: id) } else { PlanView(id: id) }
            }
        }
    }
}

struct PlanRow: View {
    @EnvironmentObject var model: AppModel
    let plan: PlanSummary

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(plan.goal).font(.headline).lineLimit(3)
            HStack(spacing: 6) {
                if let r = plan.risk { BadgeView(r.rawValue, l: model.l) }
                BadgeView(plan.finalVerdict.rawValue, l: model.l)
                Text("\(plan.target) · \(plan.steps)").font(.caption).foregroundStyle(Theme.neutral400)
                Spacer()
                if plan.status == "awaiting_approval", let exp = Format.parse(plan.expiresAt) {
                    TimelineView(.periodic(from: .now, by: 1)) { ctx in
                        let left = exp.timeIntervalSince(ctx.date)
                        Text(Format.countdown(left)).font(.caption.monospacedDigit())
                            .foregroundStyle(left < 300 ? Theme.warn : Theme.neutral400)
                    }
                }
            }
            if plan.status == "reviewing" {
                Text(model.l.t("◌ Re-reviewing your edits")).font(.caption).foregroundStyle(Theme.accent300)
            }
            if let w = PlanLogic.agentWarning(target: plan.target, agent: plan.agent, model.l) {
                Text(w.0).font(.caption).foregroundStyle(w.1.color)
            }
        }
        .padding(.vertical, 4)
    }
}
