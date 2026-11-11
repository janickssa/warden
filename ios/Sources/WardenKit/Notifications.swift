import UserNotifications
import WardenCore

/// README 17.4 notification categories. APPROVAL: Approve (Face ID) and Reject; the content extension
/// shows every command first. OPEN: high risk, failures, refusals, schedules: open the app.
public enum Notifications {
    public static let approval = "APPROVAL"
    public static let open = "OPEN"
    public static let approve = "APPROVE"
    public static let reject = "REJECT"

    public static func registerCategories(_ l: L) {
        let approve = UNNotificationAction(identifier: Self.approve, title: l.t("Approve (Face ID)"), options: [.authenticationRequired])
        let reject = UNNotificationAction(identifier: Self.reject, title: l.t("Reject"), options: [.destructive, .authenticationRequired])
        UNUserNotificationCenter.current().setNotificationCategories([
            UNNotificationCategory(identifier: approval, actions: [approve, reject], intentIdentifiers: [], options: []),
            UNNotificationCategory(identifier: open, actions: [], intentIdentifiers: [], options: []),
        ])
    }

    /// The plan or schedule a notification is about (`subject` in Warden's payload).
    public static func subject(_ userInfo: [AnyHashable: Any]) -> String? {
        guard let s = userInfo["subject"] as? String, s.hasPrefix("pln_") || s.hasPrefix("sch_"), s.count <= 40 else { return nil }
        return s
    }
}
