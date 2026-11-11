import Foundation
import WardenCore

/// Talks to Warden for the app and the notification extension. Every decision that needs your signature
/// asks for Face ID once and signs with the device key; Warden and the agents check that signature.
public struct Session: Sendable {
    public let api: APIClient
    public let l: L

    public init?(server: URL? = Store.server) {
        guard let server, let api = APIClient(server: server, transport: URLSessionTransport(cookies: Store.cookies)) else {
            return nil
        }
        self.api = api
        l = Store.l
    }

    func authenticator(_ key: DeviceKey) -> DeviceAuthenticator { DeviceAuthenticator(rp: api.rp, signer: key) }

    /// Pair: register a new device key through the one-time link, then sign in with it (two signatures,
    /// one Face ID: same context).
    public static func pair(_ link: PairingLink, deviceName: String) async throws -> Session {
        Store.forget()
        Store.server = link.server
        guard let s = Session(server: link.server) else { throw APIError.badResponse }
        let key = try DeviceKey.create(reason: s.l.t("Pair this iPhone with Warden"))
        let a = s.authenticator(key)
        let o = try await s.api.registrationOptions(token: link.token)
        guard let challenge = o.challenge else { throw APIError.badResponse }
        _ = try await s.api.register(SignedChallenge(challengeId: o.challengeId, credential: try a.create(challenge: challenge)))
        try await s.signIn(with: key)
        return s
    }

    func signIn(with key: DeviceKey) async throws {
        let o = try await api.loginOptions()
        guard let challenge = o.challenge else { throw APIError.badResponse }
        _ = try await api.login(SignedChallenge(challengeId: o.challengeId, credential: try await authenticator(key).get(challenge: challenge)))
        if let status = try? await api.status() { Store.language = status.language }
    }

    /// Run `body`; if the 12 h session ended, sign in again with the same Face ID context and retry once.
    func withSession<T>(_ key: DeviceKey?, _ body: () async throws -> T) async throws -> T {
        do {
            return try await body()
        } catch APIError.signedOut {
            guard let key = try key ?? DeviceKey.load(reason: l.t("Sign in to Warden")) else { throw APIError.signedOut }
            try await signIn(with: key)
            return try await body()
        }
    }

    /// Reads that need a session: signed out → one Face ID to sign in again.
    public func read<T>(_ body: (APIClient) async throws -> T) async throws -> T {
        try await withSession(nil) { try await body(api) }
    }

    func key(_ reason: String) throws -> DeviceKey {
        guard let key = try DeviceKey.load(reason: reason) else { throw APIError.signedOut }
        return key
    }

    /// Approve with Face ID (README 17.4): the passkey assertion is over this exact approval.
    public func approve(_ plan: PlanDetail) async throws -> PlanDetail {
        let key = try key(l.t("Approve {id} on {target}", ["id": plan.id, "target": plan.target]))
        return try await withSession(key) {
            let o = try await api.approvalOptions(plan.id)
            var signed: SignedChallenge?
            if let c = o.challenge, let challenge = c.challenge {
                signed = SignedChallenge(challengeId: c.challengeId, credential: try await authenticator(key).get(challenge: challenge))
            }
            return try await api.approve(plan.id, hash: plan.hash, signed: signed)
        }
    }

    public func reject(_ plan: PlanDetail, reason: String?) async throws -> PlanDetail {
        try await read { try await $0.reject(plan.id, reason: reason) }
    }

    public func approveSchedule(_ id: String, name: String) async throws -> ScheduleDetail {
        let key = try key(l.t("Approve schedule {name} with your passkey", ["name": name]))
        return try await withSession(key) {
            let o = try await api.scheduleApprovalOptions(id)
            guard let c = o.challenge, let challenge = c.challenge else { throw APIError.badResponse }
            return try await api.approveSchedule(id, SignedChallenge(challengeId: c.challengeId, credential: try await authenticator(key).get(challenge: challenge)))
        }
    }

    /// Lockdown (README 7A): after the press-and-hold, Face ID confirms it like the dashboard's passkey.
    public func lockdown() async throws -> PublishResult {
        let key = try key(l.t("Confirm lockdown with your passkey"))
        return try await withSession(key) {
            let o = try await api.confirmOptions(purpose: "lockdown")
            guard let challenge = o.challenge else { throw APIError.badResponse }
            return try await api.lockdown(SignedChallenge(challengeId: o.challengeId, credential: try await authenticator(key).get(challenge: challenge)))
        }
    }

    public func registerPush(token: String, deviceName: String) async throws {
        _ = try await read { try await $0.registerDevice(token: token, name: deviceName) }
    }

    public static func unpair() {
        DeviceKey.remove()
        Store.forget()
    }
}
