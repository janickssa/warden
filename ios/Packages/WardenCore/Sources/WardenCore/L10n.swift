import Foundation

/// English or Dansk (README 17.2), following Warden's `ui.language`. The English text is the key; commands,
/// IDs and policy paths are never translated. `L10nTests` fails if a `L.t("…")` in the app has no Danish.
public struct L: Sendable {
    public var lang: String

    public init(_ lang: String = "en") { self.lang = lang }

    public func t(_ key: String, _ vars: [String: CustomStringConvertible] = [:]) -> String {
        var s = lang == "da" ? (Danish.table[key] ?? key) : key
        for (k, v) in vars { s = s.replacingOccurrences(of: "{\(k)}", with: v.description) }
        return s
    }
}
