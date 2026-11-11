import SwiftUI
import UIKit
import UserNotifications
import UserNotificationsUI
import WardenCore
import WardenKit

/// Approve from the lock screen (M8 Done-when, README 17.4). Long-press an "Approval needed"
/// notification: this extension fetches the plan from Warden over WireGuard and shows every command;
/// Approve asks for Face ID and signs right here; Reject rejects. High-risk plans and anything that isn't
/// waiting any more only open the app. Commands never travel through Apple: the push only has the ID.
@objc(NotificationViewController)
final class NotificationViewController: UIViewController, UNNotificationContentExtension {
    let state = NotifyState()

    override func viewDidLoad() {
        super.viewDidLoad()
        let host = UIHostingController(rootView: NotifyView(state: state))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        host.view.backgroundColor = .clear
        view.addSubview(host.view)
        host.didMove(toParent: self)
        preferredContentSize = CGSize(width: view.bounds.width, height: 460)
    }

    func didReceive(_ notification: UNNotification) {
        guard let id = Notifications.subject(notification.request.content.userInfo), id.hasPrefix("pln_") else { return }
        state.planID = id
        Task { await state.load() }
    }

    func didReceive(_ response: UNNotificationResponse, completionHandler completion: @escaping (UNNotificationContentExtensionResponseOption) -> Void) {
        switch response.actionIdentifier {
        case Notifications.approve:
            Task { @MainActor in completion(await state.approve() ? .dismiss : .doNotDismiss) }
        case Notifications.reject:
            Task { @MainActor in completion(await state.reject() ? .dismiss : .doNotDismiss) }
        default:
            completion(.dismissAndForwardAction)  // open the app on this plan
        }
    }
}

@MainActor
final class NotifyState: ObservableObject {
    @Published var plan: PlanDetail?
    @Published var message: String?
    @Published var busy = false
    var planID: String?
    let l = Store.l

    func load() async {
        guard let id = planID, let s = Session() else {
            message = l.t("Open Warden to pair this iPhone first.")
            return
        }
        do {
            plan = try await s.read { try await $0.plan(id) }
        } catch {
            message = describe(error)
        }
    }

    /// Approve only what's on screen: a waiting plan, not high risk (README 17.4), loaded from Warden.
    func approve() async -> Bool {
        if plan == nil { await load() }
        guard let p = plan, let s = Session() else { return false }
        guard p.status == "awaiting_approval", !PlanLogic.isExpired(p, now: Date()) else {
            message = l.t("This plan isn’t waiting for approval any more.")
            return false
        }
        guard PlanLogic.canApproveFromNotification(risk: p.risk) else {
            message = l.t("High-risk plans are approved in the app. Tap to open it.")
            return false
        }
        busy = true
        defer { busy = false }
        do {
            plan = try await s.approve(p)
            return true
        } catch {
            message = describe(error)
            return false
        }
    }

    func reject() async -> Bool {
        if plan == nil { await load() }
        guard let p = plan, let s = Session() else { return false }
        do {
            plan = try await s.reject(p, reason: nil)
            return true
        } catch {
            message = describe(error)
            return false
        }
    }

    func describe(_ error: Error) -> String {
        switch error {
        case APIError.offline: return l.t("Can’t reach Warden. Is WireGuard connected?")
        case APIError.refused(_, _, let m): return m
        case let e as LocalizedError: return e.errorDescription ?? "\(error)"
        default: return "\(error)"
        }
    }
}

struct NotifyView: View {
    @ObservedObject var state: NotifyState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let p = state.plan {
                    PlanHeaderView(plan: p, l: state.l)
                    VerdictsView(plan: p, l: state.l)
                    StepsView(plan: p, l: state.l)
                } else if state.message == nil {
                    ProgressView().frame(maxWidth: .infinity)
                }
                if let m = state.message {
                    Text(m).font(.footnote).foregroundStyle(Theme.warn)
                }
                if state.busy {
                    Text(state.l.t("Waiting for Face ID…")).font(.footnote).foregroundStyle(Theme.accent300)
                }
            }
            .padding(14)
        }
        .background(Theme.bg)
        .preferredColorScheme(.dark)
    }
}
