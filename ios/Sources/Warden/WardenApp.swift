import SwiftUI
import UIKit
import UserNotifications
import WardenCore
import WardenKit

@main
struct WardenApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject var model = AppModel.shared
    @Environment(\.scenePhase) var phase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .preferredColorScheme(.dark)
                .tint(Theme.accent)
                .onChange(of: phase) { _, now in
                    if now == .active { model.start() } else { model.stop() }
                }
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        Notifications.registerCategories(Store.l)
        if Store.server != nil { application.registerForRemoteNotifications() }
        return true
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        Store.pushToken = token
        let name = UIDevice.current.name
        Task { try? await Session()?.registerPush(token: token, deviceName: name) }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {}

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list, .sound]
    }

    /// A tap, or an action the content extension forwarded: open that plan or schedule in the app.
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        guard let subject = Notifications.subject(response.notification.request.content.userInfo) else { return }
        await MainActor.run { AppModel.shared.open(subject) }
    }
}
