import Foundation

/// The one-time link from Settings → Pair iPhone (or `warden passkey add iPhone`):
/// `https://warden.example.dk/register?token=…`. Pasted into the app; nothing else is needed.
public struct PairingLink: Equatable, Sendable {
    public let server: URL
    public let token: String

    public init?(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let c = URLComponents(string: trimmed), let url = c.url, RelyingParty(serverURL: url) != nil,
              c.path.hasSuffix("/register"),
              let token = c.queryItems?.first(where: { $0.name == "token" })?.value,
              token.count >= 16, token.count <= 100,
              token.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
        else { return nil }
        var base = c
        base.path = String(c.path.dropLast("/register".count))
        base.query = nil
        base.fragment = nil
        guard let server = base.url else { return nil }
        self.server = server
        self.token = token
    }
}
