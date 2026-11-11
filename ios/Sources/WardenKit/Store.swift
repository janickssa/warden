import Foundation
import WardenCore

/// What the app and its notification extension share through the App Group: the server, the language and
/// the session cookie (httpOnly, set by Warden). No token or secret lives here: signing is the Secure
/// Enclave key's job, and it never leaves the device.
public enum Store {
    public static let appGroup = "group.dk.schwabejss.warden"

    static var defaults: UserDefaults { UserDefaults(suiteName: appGroup) ?? .standard }

    public static var server: URL? {
        get { defaults.string(forKey: "server").flatMap(URL.init(string:)) }
        set { defaults.set(newValue?.absoluteString, forKey: "server") }
    }

    public static var language: String {
        get { defaults.string(forKey: "language") ?? "en" }
        set { defaults.set(newValue, forKey: "language") }
    }

    public static var pushToken: String? {
        get { defaults.string(forKey: "pushToken") }
        set { defaults.set(newValue, forKey: "pushToken") }
    }

    public static var cookies: HTTPCookieStorage {
        HTTPCookieStorage.sharedCookieStorage(forGroupContainerIdentifier: appGroup)
    }

    public static func forget() {
        for key in ["server", "language", "pushToken"] { defaults.removeObject(forKey: key) }
        for c in cookies.cookies ?? [] { cookies.deleteCookie(c) }
    }

    public static var l: L { L(language) }
}
