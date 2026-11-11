import SwiftUI
import UIKit
import WardenCore
import WardenKit

/// Schedules (README 17.4): next run and last result; pause needs no approval, approving uses Face ID.
struct SchedulesView: View {
    @EnvironmentObject var model: AppModel
    @State var schedules: [ScheduleView] = []

    var body: some View {
        NavigationStack(path: $model.schedulePath) {
            List(schedules) { s in
                NavigationLink(value: s.id) {
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(s.name).font(.subheadline.monospaced())
                            Spacer()
                            Text(stateText(s.status)).font(.caption).foregroundStyle(s.status == "active" ? Theme.ok : s.status == "awaiting_approval" ? Theme.warn : Theme.neutral400)
                        }
                        Text("\(s.target) · \(CronText.describe(s.cron, model.l))").font(.caption).foregroundStyle(Theme.neutral300)
                        if let next = s.nextRun.flatMap(Format.parse) {
                            Text(model.l.t("Next run") + " " + Format.exact(next)).font(.caption2).foregroundStyle(Theme.neutral400)
                        }
                        if let r = s.lastResult {
                            Text("\(r) · \(s.lastDetail ?? "")").font(.caption2).foregroundStyle(r == "succeeded" ? Theme.ok : r == "failed" ? Theme.danger : Theme.warn)
                        }
                    }
                }
            }
            .overlay {
                if schedules.isEmpty { Text(model.l.t("No schedules yet")).foregroundStyle(Theme.neutral400) }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg)
            .navigationTitle(model.l.t("Schedules"))
            .navigationDestination(for: String.self) { id in
                if id.hasPrefix("sch_") { ScheduleDetailView(id: id) } else { PlanView(id: id) }
            }
            .refreshable { await load() }
            .task { await load() }
        }
    }

    func stateText(_ status: String) -> String {
        switch status {
        case "awaiting_approval": model.l.t("⏸ Awaiting approval")
        case "active": model.l.t("Active")
        case "paused": model.l.t("Paused")
        case "stopped": model.l.t("■ Stopped")
        case "expired": model.l.t("— Expired")
        case "invalidated": model.l.t("⊘ Invalidated")
        default: status
        }
    }

    func load() async {
        if let list = try? await model.session?.read({ try await $0.schedules() }) { schedules = list }
    }
}

struct ScheduleDetailView: View {
    @EnvironmentObject var model: AppModel
    let id: String
    @State var schedule: ScheduleDetail?
    @State var reviewed = false
    @State var error: String?
    @State var busy = false

    var body: some View {
        ScrollView {
            if let s = schedule {
                VStack(alignment: .leading, spacing: 14) {
                    Text(s.name).font(.title3.monospaced())
                    Text("\(s.target) · \(CronText.describe(s.cron, model.l)) · Europe/Copenhagen").font(.footnote).foregroundStyle(Theme.neutral300)
                    Text(s.goal).font(.subheadline)
                    StepsView(steps: s.stepList, l: model.l)
                    Color.clear.frame(height: 1).onAppear { reviewed = true }
                    if let error { Text(error).font(.footnote).foregroundStyle(Theme.danger) }
                    if s.status == "awaiting_approval" {
                        Button {
                            Task { await approve(s) }
                        } label: {
                            Label(busy ? model.l.t("Waiting for Face ID…") : model.l.t("Approve & sign…"), systemImage: "faceid").frame(maxWidth: .infinity, minHeight: 44)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!reviewed || busy || model.offline)
                    } else if s.status == "active" {
                        Button(model.l.t("Pause")) { Task { await act { try await $0.pauseSchedule(s.id) } } }.buttonStyle(.bordered)
                    } else if s.status == "paused" {
                        Button(model.l.t("Resume")) { Task { await act { try await $0.resumeSchedule(s.id) } } }.buttonStyle(.borderedProminent)
                    }
                    if !s.runs.isEmpty {
                        Text(model.l.t("Recent runs")).font(.caption.weight(.semibold)).textCase(.uppercase).foregroundStyle(Theme.neutral400)
                        ForEach(s.runs) { r in
                            NavigationLink(value: r.id) {
                                let b = Badge.of(r.status, model.l)
                                Text("\(b.0) · \(r.slot.flatMap(Format.parse).map(Format.exact) ?? r.id)").font(.footnote).foregroundStyle(b.1.color)
                            }
                        }
                    }
                }
                .padding(16)
            } else {
                ProgressView().padding(40)
            }
        }
        .background(Theme.bg)
        .task { await load() }
    }

    func load() async {
        do {
            schedule = try await model.session?.read { try await $0.schedule(id) }
        } catch {
            self.error = model.describe(error)
        }
    }

    func approve(_ s: ScheduleDetail) async {
        busy = true
        defer { busy = false }
        do {
            schedule = try await model.session?.approveSchedule(s.id, name: s.name)
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } catch {
            self.error = model.describe(error)
        }
    }

    func act(_ body: (APIClient) async throws -> ScheduleView) async {
        do {
            _ = try await model.session?.read(body)
            await load()
        } catch {
            self.error = model.describe(error)
        }
    }
}
