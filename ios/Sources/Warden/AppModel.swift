import SwiftUI
import UIKit
import UserNotifications
import WardenCore
import WardenKit

/// The app's state. Live by polling every 5 s while the app is open (pushes cover the rest).
@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()

    @Published var paired = Store.server != nil
    @Published var status: StatusView?
    @Published var approvals: [PlanSummary] = []
    @Published var offline = false
    @Published var lastUpdated: Date?
    @Published var error: String?
    @Published var planPath: [String] = []  // plans to show (from notifications)
    @Published var schedulePath: [String] = []
    @Published var tab = 0
    var timer: Task<Void, Never>?

    var l: L { Store.l }
    var session: Session? { Session() }

    func start() {
        guard paired, timer == nil else { return }
        timer = Task { [weak self] in
            while !Task.isCancelled {
                await self?.refresh()
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    func refresh() async {
        guard let s = session else { return }
        do {
            let (st, list) = try await s.read { api in (try await api.status(), try await api.approvals()) }
            status = st
            approvals = list.plans
            Store.language = st.language
            offline = false
            lastUpdated = Date()
            UNUserNotificationCenter.current().setBadgeCount(st.awaiting) { _ in }
        } catch APIError.offline {
            offline = true
        } catch {
            self.error = describe(error)
        }
    }

    func open(_ subject: String) {
        if subject.hasPrefix("sch_") {
            tab = 2
            schedulePath = [subject]
        } else {
            tab = 0
            planPath = [subject]
        }
    }

    func didPair() {
        paired = true
        Notifications.registerCategories(l)
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, _ in
            if granted { DispatchQueue.main.async { UIApplication.shared.registerForRemoteNotifications() } }
        }
        start()
    }

    func unpair() {
        stop()
        Session.unpair()
        paired = false
        status = nil
        approvals = []
    }

    func describe(_ error: Error) -> String {
        switch error {
        case APIError.offline: return l.t("Can’t reach Warden. Is WireGuard connected?")
        case APIError.signedOut: return l.t("Sign in again with Face ID.")
        case APIError.refused(_, _, let message): return message
        case let e as LocalizedError: return e.errorDescription ?? "\(error)"
        default: return "\(error)"
        }
    }
}
