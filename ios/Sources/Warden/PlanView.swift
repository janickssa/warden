import SwiftUI
import UIKit
import WardenCore
import WardenKit

/// Plan detail (spec 5, README 17.4): header → verdicts → steps → diff, then the decision. Approve needs
/// Face ID; high-risk plans also need you to scroll through every step first.
struct PlanView: View {
    @EnvironmentObject var model: AppModel
    let id: String
    @State var plan: PlanDetail?
    @State var reviewed = false
    @State var busy = false
    @State var error: String?
    @State var sheet: Sheet?
    @State var now = Date()

    enum Sheet: Identifiable {
        case reject, edit, output(Int)
        var id: String {
            switch self {
            case .reject: "reject"
            case .edit: "edit"
            case .output(let n): "output-\(n)"
            }
        }
    }

    var l: L { model.l }

    var body: some View {
        ScrollView {
            if let plan {
                VStack(alignment: .leading, spacing: 18) {
                    PlanHeaderView(plan: plan, l: l)
                    if plan.status == "awaiting_approval", let exp = Format.parse(plan.expiresAt) {
                        TimelineView(.periodic(from: .now, by: 1)) { ctx in
                            Label(l.t("Expires in {left} · {time}", ["left": Format.countdown(exp.timeIntervalSince(ctx.date)), "time": Format.time(exp)]), systemImage: "timer")
                                .font(.footnote.monospacedDigit())
                                .foregroundStyle(exp.timeIntervalSince(ctx.date) < 300 ? Theme.warn : Theme.neutral400)
                        }
                    }
                    if let note = plan.humanNote {
                        Text(l.t("Your note:") + " “\(note)”").font(.footnote).foregroundStyle(Theme.neutral300)
                    }
                    ForEach(plan.diagnoses, id: \.id) { d in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(l.t("Diagnosis") + " · \(d.by)").font(.caption).foregroundStyle(Theme.accent300)
                            Text(d.note).font(.footnote)
                        }
                        .padding(10)
                        .background(Theme.accent900, in: RoundedRectangle(cornerRadius: 8))
                    }
                    VerdictsView(plan: plan, l: l)
                    StepsView(plan: plan, l: l)
                    if plan.stepList.contains(where: { $0.status != nil }) {
                        HStack {
                            ForEach(plan.stepList.filter { $0.status != nil }) { s in
                                Button(l.t("Output") + " \(s.n)") { sheet = .output(s.n) }.font(.caption)
                            }
                        }
                    }
                    if !plan.diff.isEmpty { DiffView(rows: plan.diff, l: l) }
                    Color.clear.frame(height: 1).onAppear { reviewed = true }  // the end of the last step is on screen
                }
                .padding(16)
            } else if let error {
                Text(error).foregroundStyle(Theme.danger).padding()
            } else {
                ProgressView().padding(40)
            }
        }
        .background(Theme.bg)
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .bottom) { if let plan { bar(plan) } }
        .task(id: id) {
            while !Task.isCancelled {
                await load()
                try? await Task.sleep(for: .seconds(plan?.status == "running" ? 2 : 5))
            }
        }
        .sheet(item: $sheet) { s in
            switch s {
            case .reject: RejectSheet(plan: plan!) { updated in plan = updated }
            case .edit: EditSheet(plan: plan!) { updated in plan = updated; reviewed = false }
            case .output(let n): OutputSheet(planID: id, step: n)
            }
        }
    }

    func load() async {
        guard let s = model.session else { return }
        do {
            plan = try await s.read { try await $0.plan(id) }
            now = Date()
        } catch {
            if plan == nil { self.error = model.describe(error) }
        }
    }

    @ViewBuilder func bar(_ plan: PlanDetail) -> some View {
        VStack(spacing: 8) {
            if let error { Text(error).font(.footnote).foregroundStyle(Theme.danger) }
            if plan.status == "awaiting_approval" && !PlanLogic.isExpired(plan, now: Date()) {
                let gated = PlanLogic.needsScrollGate(plan) && !reviewed
                Text(model.offline ? l.t("Read-only while Warden is unreachable.")
                     : gated ? l.t("Scroll to the last step to enable Approve.")
                     : l.t("All steps reviewed. Your passkey signs the approval."))
                    .font(.caption).foregroundStyle(Theme.neutral400)
                HStack(spacing: 10) {
                    Button(l.t("Reject")) { sheet = .reject }
                        .buttonStyle(.bordered).frame(maxWidth: .infinity, minHeight: 44)
                    Button(l.t("Edit")) { sheet = .edit }
                        .buttonStyle(.bordered).frame(maxWidth: .infinity, minHeight: 44)
                    Button {
                        Task { await approve(plan) }
                    } label: {
                        Label(busy ? l.t("Waiting for Face ID…") : l.t("Approve"), systemImage: "faceid").frame(maxWidth: .infinity, minHeight: 44)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(gated || busy || model.offline)
                }
                .disabled(model.offline)
            } else if plan.status == "running" {
                HoldButton(title: l.t("Kill switch"), holding: l.t("Keep holding… {s} s", ["s": 2]), systemImage: "stop.circle.fill") {
                    Task { await kill(plan) }
                }
            } else if let info = PlanLogic.info(plan, now: Date(), l) {
                Text(info.0).font(.footnote).foregroundStyle(info.1.color).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(12)
        .background(Theme.bg.opacity(0.97))
        .overlay(alignment: .top) { Divider() }
    }

    func approve(_ p: PlanDetail) async {
        guard let s = model.session else { return }
        busy = true
        defer { busy = false }
        do {
            plan = try await s.approve(p)
            error = nil
            UINotificationFeedbackGenerator().notificationOccurred(.success)
        } catch {
            self.error = model.describe(error)
        }
    }

    func kill(_ p: PlanDetail) async {
        guard let s = model.session else { return }
        do {
            _ = try await s.read { try await $0.kill(p.id) }
        } catch {
            self.error = model.describe(error)
        }
    }
}

struct DiffView: View {
    let rows: [DiffRow]
    let l: L

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(l.t("Diff vs. previous")).font(.caption.weight(.semibold)).textCase(.uppercase).foregroundStyle(Theme.neutral400)
            ForEach(Array(rows.enumerated()), id: \.offset) { _, r in
                VStack(alignment: .leading, spacing: 2) {
                    if r.op != "added", let old = r.oldCommand {
                        Text("− \(old)").font(.caption.monospaced()).foregroundStyle(r.op == "removed" ? Theme.danger : Theme.neutral400)
                    }
                    if r.op != "removed", let new = r.newCommand {
                        Text((r.op == "added" ? "+ " : "  ") + new).font(.caption.monospaced()).foregroundStyle(r.op == "added" ? Theme.ok : Theme.neutral200)
                    }
                }
            }
        }
    }
}

struct RejectSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    let plan: PlanDetail
    let done: (PlanDetail) -> Void
    @State var reason = ""
    @State var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Text(model.l.t("Claude will be told the plan was rejected, with your reason if you give one."))
                TextField(model.l.t("e.g. Use port 3001 instead"), text: $reason, axis: .vertical)
                if let error { Text(error).foregroundStyle(Theme.danger) }
            }
            .navigationTitle(model.l.t("Reject plan"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(model.l.t("Cancel")) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(model.l.t("Reject plan")) {
                        Task {
                            do {
                                let trimmed = reason.trimmingCharacters(in: .whitespacesAndNewlines)
                                done(try await model.session!.reject(plan, reason: trimmed.isEmpty ? nil : trimmed))
                                dismiss()
                            } catch {
                                self.error = model.describe(error)
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Approve with edits (README 17.4): each step shows the original and your version; submitting sends the
/// plan back to policy and every gatekeeper, and approving still needs Face ID.
struct EditSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    let plan: PlanDetail
    let done: (PlanDetail) -> Void
    @State var drafts: [Int: String] = [:]
    @State var error: String?

    var body: some View {
        NavigationStack {
            Form {
                Text(model.l.t("You’re editing commands. Submitting creates a new plan hash; policy and every gatekeeper review it again before you can approve."))
                    .font(.footnote)
                ForEach(plan.stepList) { s in
                    Section("\(s.n). \(s.purpose)") {
                        Text(s.command).font(.footnote.monospaced()).foregroundStyle(Theme.neutral400)
                        TextEditor(text: Binding(get: { drafts[s.n] ?? s.command }, set: { drafts[s.n] = $0 }))
                            .font(.footnote.monospaced())
                            .frame(minHeight: 60)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                }
                if let error { Text(error).foregroundStyle(Theme.danger) }
            }
            .navigationTitle(model.l.t("Approve with edits"))
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(model.l.t("Cancel")) { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(model.l.t("Submit edits for review")) {
                        let edits = plan.stepList.compactMap { s -> (Int, String)? in
                            guard let d = drafts[s.n], d != s.command else { return nil }
                            return (s.n, d)
                        }
                        guard !edits.isEmpty else { dismiss(); return }
                        Task {
                            do {
                                done(try await model.session!.read { try await $0.approveWithEdits(plan.id, edits: edits) })
                                dismiss()
                            } catch {
                                self.error = model.describe(error)
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Full-screen output with ANSI colours, copy and the cap note (README 17.4).
struct OutputSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    let planID: String
    let step: Int
    @State var text = ""
    @State var capped = false

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(text.split(separator: "\n", omittingEmptySubsequences: false).enumerated()), id: \.offset) { _, line in
                        ANSIText(line: String(line))
                    }
                    if capped {
                        Text(model.l.t("⋯ warden-agent: output truncated · the step kept running, the rest wasn’t kept"))
                            .font(.caption.monospaced()).foregroundStyle(Theme.warn)
                    }
                }
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Theme.bg)
            .navigationTitle(model.l.t("Output") + " · \(step)")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(model.l.t("Close")) { dismiss() } }
                ToolbarItem(placement: .primaryAction) {
                    Button(model.l.t("Copy")) { UIPasteboard.general.string = ANSI.strip(text) }
                }
            }
            .task {
                while !Task.isCancelled {
                    if let out = try? await model.session?.read({ try await $0.output(planID) }) {
                        text = out.chunks.filter { $0.n == step }.map(\.data).joined()
                        capped = text.utf8.count >= out.capBytes
                    }
                    try? await Task.sleep(for: .seconds(2))
                }
            }
        }
    }
}

struct ANSIText: View {
    let line: String

    var body: some View {
        ANSI.spans(line).reduce(Text("")) { acc, span in
            acc + Text(span.text)
                .foregroundColor(span.colour?.color ?? Theme.neutral300)
                .fontWeight(span.bold ? .semibold : .regular)
        }
        .font(.caption.monospaced())
        .textSelection(.enabled)
    }
}
