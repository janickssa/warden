import Foundation

// The dashboard API's shapes (backend/src/warden/api/schemas.py), decoded with snake_case keys. Fields the
// app doesn't use are left out; optional ones are optional so an older or newer Warden still decodes.

public enum Verdict: String, Codable, Sendable { case allow, escalate, deny }
public enum Risk: String, Codable, Sendable, Comparable {
    case low, medium, high
    public static func < (a: Risk, b: Risk) -> Bool { a.rank < b.rank }
    var rank: Int { switch self { case .low: 0; case .medium: 1; case .high: 2 } }
}

public struct AgentState: Codable, Equatable, Sendable {
    public var state: String  // current | behind | offline | revoked | missing | lockdown
    public var warning: String?
    public var policyVersion: Int?
    public var latestVersion: Int?
}

public struct PlanSummary: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var status: String
    public var goal: String
    public var target: String
    public var revises: String?
    public var requestedBy: String
    public var steps: Int
    public var createdAt: String
    public var expiresAt: String
    public var risk: Risk?
    public var finalVerdict: Verdict
    public var gatekeeperUnavailable: Bool
    public var heldReason: String?
    public var failedAt: Int?
    public var failReason: String?
    public var invalidatedBy: Int?
    public var changedSteps: Int?
    public var decidedAt: String?
    public var agent: AgentState?
    public var scheduleId: String?
    public var slot: String?
}

public struct StepView: Codable, Equatable, Identifiable, Sendable {
    public var n: Int
    public var kind: String
    public var command: String
    public var purpose: String
    public var cwd: String
    public var timeoutS: Int
    public var expectExit: Int
    public var edited: Bool
    public var status: String?
    public var exitCode: Int?
    public var reason: String?
    public var durationS: Double?
    public var outputTruncated: Bool?
    public var id: Int { n }
}

public struct Reviewer: Codable, Equatable, Sendable {
    public var name: String
    public var model: String
    public var verdict: Verdict
    public var risk: Risk
    public var summary: String
    public var unavailable: Bool
    public var notes: [String: String]?
}

public struct ApprovalView: Codable, Equatable, Sendable {
    public var by: String
    public var at: String
    public var hash: String
    public var keyId: String
    public var passkey: String?
}

public struct DiffRow: Codable, Equatable, Sendable {
    public var op: String  // same | added | removed
    public var oldN: Int?
    public var newN: Int?
    public var oldCommand: String?
    public var newCommand: String?
    public var oldStatus: String?
}

public struct Evidence: Codable, Equatable, Sendable {
    public var auditId: Int
    public var command: String
    public var exitCode: Int?
    public var output: String
}

public struct Diagnosis: Codable, Equatable, Sendable {
    public var id: String
    public var by: String
    public var note: String
    public var createdAt: String
    public var evidence: [Evidence]
}

public struct Violation: Codable, Equatable, Sendable {
    public var code: String
    public var message: String
    public var step: Int?
}

public struct PlanDetail: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var status: String
    public var goal: String
    public var target: String
    public var revises: String?
    public var requestedBy: String
    public var steps: Int
    public var createdAt: String
    public var expiresAt: String
    public var risk: Risk?
    public var finalVerdict: Verdict
    public var gatekeeperUnavailable: Bool
    public var heldReason: String?
    public var failedAt: Int?
    public var failReason: String?
    public var invalidatedBy: Int?
    public var changedSteps: Int?
    public var agent: AgentState?
    public var scheduleId: String?
    public var hash: String
    public var policyOk: Bool
    public var policyVersion: Int
    public var violations: [Violation]
    public var reviewers: [Reviewer]
    public var reviewersDisagree: Bool
    public var stepList: [StepView]
    public var approval: ApprovalView?
    public var invalidReason: String?
    public var rejectReason: String?
    public var diff: [DiffRow]
    public var diagnoses: [Diagnosis]
    public var revisions: [String]
    public var passkeyReasons: [String]
    public var e2e: Bool
    public var humanNote: String?
    public var startedAt: String?
    public var endedAt: String?
}

public struct PlanList: Codable, Equatable, Sendable {
    public var plans: [PlanSummary]
    public var counts: [String: Int]
}

public struct GatekeeperStatus: Codable, Equatable, Sendable {
    public var name: String
    public var model: String
    public var state: String  // up | unavailable | unknown
    public var why: String?
}

public struct AgentView: Codable, Equatable, Identifiable, Sendable {
    public var name: String
    public var kind: String
    public var status: String  // online | behind | offline | revoked | not_enrolled
    public var online: Bool
    public var lastSeen: String?
    public var agentVersion: String?
    public var policyVersion: Int?
    public var latestVersion: Int
    public var groups: [String]
    public var id: String { name }
}

public struct StatusView: Codable, Equatable, Sendable {
    public var me: String
    public var policyVersion: Int
    public var lockdown: Bool
    public var e2e: Bool
    public var agents: [AgentView]
    public var gatekeepers: [GatekeeperStatus]
    public var running: [String]
    public var awaiting: Int
    public var pendingPublish: Int?
    public var language: String
    public var passkeys: Int
    public var schedulesAwaiting: Int?
}

public struct FeedItem: Codable, Equatable, Identifiable, Sendable {
    public var seq: Int
    public var ts: String
    public var type: String
    public var actor: String
    public var action: String
    public var subject: String
    public var target: String?
    public var planId: String?
    public var id: Int { seq }
}

public struct Feed: Codable, Equatable, Sendable { public var items: [FeedItem] }

public struct ScheduleView: Codable, Equatable, Identifiable, Sendable {
    public var id: String
    public var name: String
    public var target: String
    public var goal: String
    public var cron: String
    public var status: String
    public var statusReason: String?
    public var expiresAt: String?
    public var expiryDays: Int
    public var nextRun: String?
    public var lastResult: String?
    public var lastDetail: String?
    public var lastRunId: String?
    public var steps: Int
}

public struct ScheduleDetail: Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var target: String
    public var goal: String
    public var cron: String
    public var status: String
    public var statusReason: String?
    public var expiresAt: String?
    public var expiryDays: Int
    public var nextRun: String?
    public var lastResult: String?
    public var lastDetail: String?
    public var stepList: [StepView]
    public var runs: [PlanSummary]
    public var risk: Risk?
}

public struct OutputChunk: Codable, Equatable, Sendable {
    public var n: Int
    public var seq: Int
    public var stream: String
    public var data: String
}

public struct OutputView: Codable, Equatable, Sendable {
    public var planId: String
    public var chunks: [OutputChunk]
    public var capBytes: Int
}

public struct Me: Codable, Equatable, Sendable {
    public var name: String
    public var expiresAt: String
}

public struct Ok: Codable, Equatable, Sendable {
    public var ok: Bool?
    public var message: String?
}

public struct PublishResult: Codable, Equatable, Sendable {
    public var outcome: String
    public var version: Int
}

/// `{challenge_id, options}` from Warden's passkey endpoints; `options` is WebAuthn's JSON.
public struct ChallengeOptions: Codable, Equatable, Sendable {
    public var challengeId: String
    public var options: JSONValue

    public var challenge: String? { options["challenge"]?.string }
}

public struct ApproveOptions: Codable, Equatable, Sendable {
    public var needsPasskey: Bool
    public var reasons: [String]
    public var challengeId: String?
    public var options: JSONValue?

    public var challenge: ChallengeOptions? {
        guard let id = challengeId, let o = options else { return nil }
        return ChallengeOptions(challengeId: id, options: o)
    }
}

public struct DeviceView: Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var passkey: String
}

/// Arbitrary JSON (WebAuthn options).
public enum JSONValue: Codable, Equatable, Sendable {
    case string(String), number(Double), bool(Bool), null
    case array([JSONValue]), object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .number(let n): try c.encode(n)
        case .bool(let b): try c.encode(b)
        case .null: try c.encodeNil()
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    public subscript(key: String) -> JSONValue? {
        if case .object(let o) = self { return o[key] }
        return nil
    }

    public var string: String? {
        if case .string(let s) = self { return s }
        return nil
    }
}

public enum WardenJSON {
    public static var decoder: JSONDecoder {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        return d
    }

    /// Request bodies spell their keys out (WebAuthn's must stay camelCase), so no key strategy here.
    public static var encoder: JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }
}
