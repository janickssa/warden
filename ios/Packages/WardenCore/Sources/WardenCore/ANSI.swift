import Foundation

/// Step output with ANSI colours (README 17.4 "monospace, ANSI colours"). SGR colours only; every other
/// escape sequence is dropped. Output is untrusted text: it's only ever shown as text.
public struct ANSISpan: Equatable, Sendable {
    public var text: String
    public var colour: Tone?
    public var bold: Bool
}

public enum ANSI {
    static let fg: [Int: Tone] = [31: .danger, 32: .ok, 33: .warn, 34: .accent, 35: .accent, 36: .accent, 90: .neutral, 91: .danger, 92: .ok, 93: .warn, 94: .accent]

    public static func spans(_ line: String) -> [ANSISpan] {
        var out: [ANSISpan] = []
        var colour: Tone? = nil
        var bold = false
        var text = ""
        var i = line.unicodeScalars.startIndex
        let scalars = line.unicodeScalars
        func flush() {
            if !text.isEmpty { out.append(ANSISpan(text: text, colour: colour, bold: bold)) }
            text = ""
        }
        while i < scalars.endIndex {
            let c = scalars[i]
            if c == "\u{1b}" {
                var j = scalars.index(after: i)
                guard j < scalars.endIndex, scalars[j] == "[" else { i = j; continue }
                j = scalars.index(after: j)
                var params = ""
                while j < scalars.endIndex, !(("@"..."~").contains(scalars[j])) {
                    params.unicodeScalars.append(scalars[j])
                    j = scalars.index(after: j)
                }
                if j < scalars.endIndex, scalars[j] == "m" {
                    flush()
                    for code in (params.isEmpty ? "0" : params).split(separator: ";", omittingEmptySubsequences: false).map({ Int($0) ?? 0 }) {
                        switch code {
                        case 0: colour = nil; bold = false
                        case 1: bold = true
                        case 22: bold = false
                        case 39: colour = nil
                        default: if let t = fg[code] { colour = t }
                        }
                    }
                }
                i = j < scalars.endIndex ? scalars.index(after: j) : j
                continue
            }
            if c.value >= 0x20 || c == "\t" { text.unicodeScalars.append(c) }
            i = scalars.index(after: i)
        }
        flush()
        return out
    }

    public static func strip(_ text: String) -> String {
        text.split(separator: "\n", omittingEmptySubsequences: false).map { spans(String($0)).map(\.text).joined() }.joined(separator: "\n")
    }
}
