import Foundation

/// Cron in plain language ("Every day at 03:00"), like the web. Warden and the agents evaluate cron.
public enum CronText {
    static let days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

    public static func describe(_ expr: String, _ l: L = L()) -> String {
        let f = expr.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard f.count == 5 else { return expr }
        let (m, h, dom, mon, dow) = (f[0], f[1], f[2], f[3], f[4])
        func num(_ s: String) -> Bool { !s.isEmpty && s.count <= 2 && s.allSatisfy(\.isNumber) }
        if expr == "* * * * *" { return l.t("Every minute") }
        if m.hasPrefix("*/"), num(String(m.dropFirst(2))), h == "*", dom == "*", mon == "*", dow == "*" {
            return l.t("Every {n} minutes", ["n": m.dropFirst(2)])
        }
        guard num(m), num(h), mon == "*" else { return expr }
        let at = String(format: "%02d:%02d", Int(h)!, Int(m)!)
        if dom == "*" && dow == "*" { return l.t("Every day at {time}", ["time": at]) }
        if dom == "*" && dow == "1-5" { return l.t("Every weekday at {time}", ["time": at]) }
        if dom == "*", dow.count == 1, let d = Int(dow), d <= 7 {
            return l.t("Every {day} at {time}", ["day": l.t(days[d % 7]), "time": at])
        }
        if dow == "*" && num(dom) { return l.t("On day {n} of every month at {time}", ["n": dom, "time": at]) }
        return expr
    }
}
