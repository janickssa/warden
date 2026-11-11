import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// How requests reach Warden. The app uses URLSession (which keeps the httpOnly session cookie in the App
/// Group's cookie store, shared with the notification extension); tests use a fake.
public protocol Transport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, Int)
}

public enum APIError: Error, Equatable, Sendable {
    /// Warden can't be reached (WireGuard off, server down): show cached data, read-only.
    case offline
    /// The session expired or was revoked: sign in again with Face ID.
    case signedOut
    /// Warden refused, with its reason (e.g. passkey_required, expired, decided_elsewhere).
    case refused(status: Int, code: String, message: String)
    case badResponse
}

struct Problem: Decodable {
    struct Detail: Decodable { var code: String?; var message: String? }
    var detail: Detail?
}

/// The dashboard API, as the browser uses it: same cookie session, `Origin` = Warden's public origin and
/// `X-Warden: 1` on every request (Warden's CSRF check). The app holds no other secret.
public struct APIClient: Sendable {
    public let server: URL
    public let rp: RelyingParty
    let transport: Transport

    public init?(server: URL, transport: Transport) {
        guard let rp = RelyingParty(serverURL: server) else { return nil }
        self.server = server
        self.rp = rp
        self.transport = transport
    }

    func request(_ method: String, _ path: String, body: Data? = nil) -> URLRequest {
        var r = URLRequest(url: server.appendingPathComponent("api").appendingPathComponent(path))
        if let q = path.firstIndex(of: "?") {  // appendingPathComponent would escape the query
            var c = URLComponents(url: server, resolvingAgainstBaseURL: false)!
            c.path = (c.path.hasSuffix("/") ? String(c.path.dropLast()) : c.path) + "/api/" + path[..<q]
            c.percentEncodedQuery = String(path[path.index(after: q)...])
            r = URLRequest(url: c.url!)
        }
        r.httpMethod = method
        r.setValue(rp.origin, forHTTPHeaderField: "Origin")
        r.setValue("1", forHTTPHeaderField: "X-Warden")
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        r.timeoutInterval = 20
        if let body {
            r.httpBody = body
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return r
    }

    public func call<T: Decodable>(_ method: String, _ path: String, body: (some Encodable)? = Optional<Empty>.none, as: T.Type = T.self) async throws -> T {
        let data = try body.map { try WardenJSON.encoder.encode($0) }
        let r = request(method, path, body: method == "POST" && data == nil ? Data("{}".utf8) : data)
        let (bytes, status): (Data, Int)
        do {
            (bytes, status) = try await transport.send(r)
        } catch {
            throw APIError.offline
        }
        if status == 502 || status == 503 || status == 504 { throw APIError.offline }
        if status == 401 { throw APIError.signedOut }
        guard (200..<300).contains(status) else {
            let p = try? WardenJSON.decoder.decode(Problem.self, from: bytes)
            throw APIError.refused(status: status, code: p?.detail?.code ?? "\(status)", message: p?.detail?.message ?? "")
        }
        do {
            return try WardenJSON.decoder.decode(T.self, from: bytes)
        } catch {
            throw APIError.badResponse
        }
    }

    public struct Empty: Codable, Sendable { public init() {} }
}

// MARK: - Endpoints

public struct SignedChallenge: Codable, Equatable, Sendable {
    public var challengeId: String
    public var credential: WebAuthnCredential
    enum CodingKeys: String, CodingKey { case challengeId = "challenge_id", credential }

    public init(challengeId: String, credential: WebAuthnCredential) {
        self.challengeId = challengeId
        self.credential = credential
    }
}

struct TokenBody: Encodable { var token: String }
struct ApproveBody: Encodable {
    var hash: String
    var challengeId: String?
    var credential: WebAuthnCredential?
    enum CodingKeys: String, CodingKey { case hash, challengeId = "challenge_id", credential }
}
struct ReasonBody: Encodable { var reason: String? }
struct EditBody: Encodable { var edits: [Edit]; struct Edit: Encodable { var n: Int; var command: String } }
struct ConfirmBody: Encodable { var purpose: String; var subject: String }
struct DeviceBody: Encodable { var token: String; var name: String }
struct SettingsBody: Encodable { var changes: [String: Bool] }

/// The notification switches (`settings.notifications`, README 17.4), as Warden stores them.
public struct NotificationPrefs: Equatable, Sendable {
    public static let keys = ["approval_needed", "plan_failed", "agent_refused", "scheduled_done"]
    public var values: [String: Bool]

    init(_ settings: JSONValue) {
        var v: [String: Bool] = [:]
        for k in Self.keys {
            if case .bool(let b)? = settings["values"]?["notifications.\(k)"] { v[k] = b }
        }
        values = v
    }
}

extension APIClient {
    public func status() async throws -> StatusView { try await call("GET", "status") }
    public func me() async throws -> Me { try await call("GET", "auth/me") }
    public func approvals() async throws -> PlanList { try await call("GET", "approvals") }
    public func plans() async throws -> PlanList { try await call("GET", "plans") }
    public func plan(_ id: String) async throws -> PlanDetail { try await call("GET", "plans/\(id)") }
    public func output(_ id: String) async throws -> OutputView { try await call("GET", "plans/\(id)/output") }
    public func feed() async throws -> Feed { try await call("GET", "feed?limit=100") }
    public func schedules() async throws -> [ScheduleView] { try await call("GET", "schedules") }
    public func schedule(_ id: String) async throws -> ScheduleDetail { try await call("GET", "schedules/\(id)") }

    // Pairing and sign-in with the Face ID device key.
    public func registrationOptions(token: String) async throws -> ChallengeOptions {
        try await call("POST", "passkeys/register/options", body: TokenBody(token: token))
    }
    public func register(_ signed: SignedChallenge) async throws -> JSONValue {
        try await call("POST", "passkeys/register", body: signed)
    }
    public func loginOptions() async throws -> ChallengeOptions { try await call("POST", "auth/options") }
    public func login(_ signed: SignedChallenge) async throws -> Me { try await call("POST", "auth/login", body: signed) }
    public func registerDevice(token: String, name: String) async throws -> DeviceView {
        try await call("POST", "devices", body: DeviceBody(token: token, name: name))
    }

    // Decisions. Approve needs a fresh assertion over this approval (README 10.0).
    public func approvalOptions(_ id: String) async throws -> ApproveOptions { try await call("POST", "plans/\(id)/approval/options") }
    public func approve(_ id: String, hash: String, signed: SignedChallenge?) async throws -> PlanDetail {
        try await call("POST", "plans/\(id)/approve", body: ApproveBody(hash: hash, challengeId: signed?.challengeId, credential: signed?.credential))
    }
    public func reject(_ id: String, reason: String?) async throws -> PlanDetail {
        try await call("POST", "plans/\(id)/reject", body: ReasonBody(reason: reason))
    }
    public func approveWithEdits(_ id: String, edits: [(Int, String)]) async throws -> PlanDetail {
        try await call("POST", "plans/\(id)/edits", body: EditBody(edits: edits.map { .init(n: $0.0, command: $0.1) }))
    }
    public func kill(_ id: String) async throws -> Ok { try await call("POST", "plans/\(id)/kill") }
    public func confirmOptions(purpose: String, subject: String = "") async throws -> ChallengeOptions {
        try await call("POST", "confirm/options", body: ConfirmBody(purpose: purpose, subject: subject))
    }
    public func lockdown(_ signed: SignedChallenge) async throws -> PublishResult { try await call("POST", "lockdown", body: signed) }
    public func notificationPrefs() async throws -> NotificationPrefs {
        NotificationPrefs(try await call("GET", "settings", as: JSONValue.self))
    }
    public func setNotification(_ key: String, _ on: Bool) async throws -> NotificationPrefs {
        NotificationPrefs(try await call("PUT", "settings", body: SettingsBody(changes: ["notifications.\(key)": on]), as: JSONValue.self))
    }
    public func pauseSchedule(_ id: String) async throws -> ScheduleView { try await call("POST", "schedules/\(id)/pause") }
    public func resumeSchedule(_ id: String) async throws -> ScheduleView { try await call("POST", "schedules/\(id)/resume") }
    public func scheduleApprovalOptions(_ id: String) async throws -> ApproveOptions {
        try await call("POST", "schedules/\(id)/approval/options")
    }
    public func approveSchedule(_ id: String, _ signed: SignedChallenge) async throws -> ScheduleDetail {
        try await call("POST", "schedules/\(id)/approve", body: signed)
    }
}

/// URLSession with a cookie store (the App Group's, so the notification extension shares the session).
public struct URLSessionTransport: Transport {
    let session: URLSession

    public init(cookies: HTTPCookieStorage = .shared) {
        let c = URLSessionConfiguration.ephemeral
        c.httpCookieStorage = cookies
        c.httpShouldSetCookies = true
        c.httpCookieAcceptPolicy = .onlyFromMainDocumentDomain
        session = URLSession(configuration: c)
    }

    public func send(_ request: URLRequest) async throws -> (Data, Int) {
        let (data, resp) = try await session.data(for: request)
        return (data, (resp as? HTTPURLResponse)?.statusCode ?? 0)
    }
}
