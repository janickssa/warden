import Foundation

/// README 17.2 formats: 20.10.2026, 14:32 (24-hour, Europe/Copenhagen), 1 min 12 s, MB/GB.
public enum Format {
    public static let zone = TimeZone(identifier: "Europe/Copenhagen")!

    static func formatter(_ pattern: String) -> DateFormatter {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_DK_POSIX")
        f.timeZone = zone
        f.dateFormat = pattern
        return f
    }

    /// Warden's ISO 8601 timestamps, with or without fractional seconds (Python writes microseconds).
    public static func parse(_ text: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: text) { return d }
        f.formatOptions = [.withInternetDateTime]
        if let d = f.date(from: text) { return d }
        // Microseconds: trim to milliseconds and retry.
        if let dot = text.firstIndex(of: "."), let end = text[dot...].firstIndex(where: { $0 == "+" || $0 == "-" || $0 == "Z" }) {
            let frac = text[text.index(after: dot)..<end].prefix(3)
            return Self.parse(String(text[..<dot]) + "." + frac + text[end...])
        }
        return nil
    }

    public static func time(_ d: Date) -> String { formatter("HH:mm").string(from: d) }
    public static func timeSeconds(_ d: Date) -> String { formatter("HH:mm:ss").string(from: d) }
    public static func date(_ d: Date) -> String { formatter("dd.MM.yyyy").string(from: d) }
    public static func exact(_ d: Date) -> String { "\(date(d)) \(time(d))" }

    public static func relative(_ d: Date, now: Date, _ l: L = L()) -> String {
        let min = Int(now.timeIntervalSince(d) / 60)
        if min < 1 { return l.t("just now") }
        if min < 60 { return l.t("{n} min ago", ["n": min]) }
        if min < 24 * 60 { return l.t("{n} h ago", ["n": min / 60]) }
        return date(d)
    }

    public static func duration(_ seconds: Double) -> String {
        let s = Int(seconds.rounded())
        return s < 60 ? "\(s) s" : "\(s / 60) min \(s % 60) s"
    }

    public static func countdown(_ seconds: Double) -> String {
        guard seconds > 0 else { return "00:00" }
        let s = Int(seconds)
        return String(format: "%02d:%02d", s / 60, s % 60)
    }

    public static func bytes(_ n: Int) -> String {
        let d = Double(n)
        if d >= 1024 * 1024 * 1024 { return String(format: "%.1f GB", d / 1024 / 1024 / 1024) }
        if d >= 1024 * 1024 { return "\(Int((d / 1024 / 1024).rounded())) MB" }
        if d >= 1024 { return "\(Int((d / 1024).rounded())) kB" }
        return "\(n) B"
    }

    /// `sha256:8f3e1c2…a1d0`: the first 11 characters, an ellipsis, the last 4.
    public static func shortHash(_ h: String) -> String { h.count > 20 ? "\(h.prefix(11))…\(h.suffix(4))" : h }
}
