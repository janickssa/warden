import SwiftUI
import UIKit
import WardenCore
import WardenKit

/// Settings (README 17.4): Lockdown (press and hold, then Face ID), agents, server, notifications per
/// event type, Test connection, unpair.
struct SettingsView: View {
    @EnvironmentObject var model: AppModel
    @State var prefs: [String: Bool] = [:]
    @State var message: String?
    @State var confirmUnpair = false

    static let prefLabels: [(String, String)] = [
        ("approval_needed", "Approval needed"), ("plan_failed", "Plan failed"),
        ("agent_refused", "Agent refused a step"), ("scheduled_done", "Scheduled run finished"),
    ]

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if model.status?.lockdown == true {
                        Text(model.l.t("■ Lockdown active")).foregroundStyle(Theme.danger)
                        Text(model.l.t("Lifting needs the offline key, in the dashboard.")).font(.footnote).foregroundStyle(Theme.neutral400)
                    } else {
                        HoldButton(title: model.l.t("Press and hold for 2 s"), holding: model.l.t("Keep holding…"), systemImage: "lock.fill") {
                            Task { await lockdown() }
                        }
                        Text(model.l.t("Publishes a tightening bundle that allows only read-only commands on every agent. Lifting it later counts as loosening and needs the offline key."))
                            .font(.footnote).foregroundStyle(Theme.neutral400)
                    }
                } header: { Text(model.l.t("Lockdown")) }

                Section(model.l.t("Agents")) {
                    ForEach(model.status?.agents ?? []) { a in
                        HStack {
                            Text(a.name)
                            Spacer()
                            Text(a.status == "online" ? "● v\(a.policyVersion ?? 0)" : a.status)
                                .font(.caption.monospaced())
                                .foregroundStyle(a.status == "online" ? Theme.ok : a.status == "behind" ? Theme.warn : Theme.danger)
                        }
                    }
                }

                Section(model.l.t("iPhone notifications")) {
                    ForEach(Self.prefLabels, id: \.0) { pref in
                        Toggle(model.l.t(pref.1), isOn: Binding(get: { prefs[pref.0] ?? true }, set: { on in Task { await setPref(pref.0, on) } }))
                    }
                }

                Section("Warden") {
                    Text(Store.server?.absoluteString ?? "—").font(.footnote.monospaced())
                    Button(model.l.t("Test connection")) { Task { await test() } }
                    if let message { Text(message).font(.footnote) }
                    Button(model.l.t("Unpair this iPhone"), role: .destructive) { confirmUnpair = true }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Theme.bg)
            .navigationTitle(model.l.t("Settings"))
            .task { await loadPrefs() }
            .confirmationDialog(model.l.t("Unpair this iPhone"), isPresented: $confirmUnpair) {
                Button(model.l.t("Unpair"), role: .destructive) { model.unpair() }
            } message: {
                Text(model.l.t("The Face ID key is deleted from this iPhone. Remove it in the dashboard too, so agents stop trusting it."))
            }
        }
    }

    func loadPrefs() async {
        if let p = try? await model.session?.read({ try await $0.notificationPrefs() }) { prefs = p.values }
    }

    func setPref(_ key: String, _ on: Bool) async {
        prefs[key] = on
        do {
            if let p = try await model.session?.read({ try await $0.setNotification(key, on) }) { prefs = p.values }
        } catch {
            message = model.describe(error)
        }
    }

    func test() async {
        do {
            let s = try await model.session?.read { try await $0.status() }
            message = model.l.t("✓ Connected · policy v{v}", ["v": s?.policyVersion ?? 0])
        } catch {
            message = model.describe(error)
        }
    }

    func lockdown() async {
        do {
            _ = try await model.session?.lockdown()
            UINotificationFeedbackGenerator().notificationOccurred(.warning)
            message = model.l.t("Lockdown active · every agent is read-only")
            await model.refresh()
        } catch {
            message = model.describe(error)
        }
    }
}
