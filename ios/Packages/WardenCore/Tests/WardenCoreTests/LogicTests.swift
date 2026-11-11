import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import WardenCore

final class LogicTests: XCTestCase {
    func reviewer(_ v: Verdict, unavailable: Bool = false) -> Reviewer {
        Reviewer(name: "r", model: "m", verdict: v, risk: .low, summary: "", unavailable: unavailable, notes: nil)
    }

    /// Bug 3: an unavailable gatekeeper counts as escalate on the iPhone too, never as allow.
    func testUnavailableGatekeeperCountsAsEscalate() {
        XCTAssertEqual(PlanLogic.finalVerdict([reviewer(.allow), reviewer(.allow, unavailable: true)]), .escalate)
        XCTAssertEqual(PlanLogic.finalVerdict([reviewer(.allow)]), .allow)
        XCTAssertEqual(PlanLogic.finalVerdict([reviewer(.deny), reviewer(.allow, unavailable: true)]), .deny)
        XCTAssertEqual(PlanLogic.finalVerdict([]), .escalate)
        let (text, tone) = PlanLogic.reviewerLine(reviewer(.allow, unavailable: true))
        XCTAssertEqual(text, "○ Unavailable · counted as escalate")
        XCTAssertEqual(tone, .warn)
        XCTAssertEqual(PlanLogic.reviewerLine(reviewer(.allow, unavailable: true), L("da")).0, "○ Utilgængelig · tæller som eskalering")
    }

    func testShownFinalIsNeverLessStrictThanWardens() throws {
        var p = try WardenJSON.decoder.decode(PlanDetail.self, from: Fixtures.raw("api_examples.json", key: "plan_waiting"))
        p.reviewers = [reviewer(.allow)]
        p.finalVerdict = .deny
        XCTAssertEqual(PlanLogic.shownFinal(p), .deny)
        p.finalVerdict = .allow
        p.reviewers = [reviewer(.allow, unavailable: true)]
        XCTAssertEqual(PlanLogic.shownFinal(p), .escalate)
    }

    func testHighRiskIsReviewedInTheAppOnly() throws {
        XCTAssertFalse(PlanLogic.canApproveFromNotification(risk: .high))
        XCTAssertTrue(PlanLogic.canApproveFromNotification(risk: .medium))
        XCTAssertTrue(PlanLogic.canApproveFromNotification(risk: nil))
        var p = try WardenJSON.decoder.decode(PlanDetail.self, from: Fixtures.raw("api_examples.json", key: "plan_waiting"))
        p.risk = .high
        XCTAssertTrue(PlanLogic.needsScrollGate(p))
        p.expiresAt = "2020-01-01T00:00:00+00:00"
        XCTAssertTrue(PlanLogic.isExpired(p, now: Date()))
        XCTAssertEqual(PlanLogic.info(p, now: Date())?.0, "Expired at 01:00. Ask Claude to propose again.")
    }

    func testAgentWarnings() {
        let behind = AgentState(state: "behind", warning: nil, policyVersion: 41, latestVersion: 42)
        XCTAssertEqual(PlanLogic.agentWarning(target: "dev2", agent: behind)?.1, .warn)
        XCTAssertTrue(PlanLogic.agentWarning(target: "dev2", agent: behind)!.0.contains("v41, latest is v42"))
        XCTAssertNil(PlanLogic.agentWarning(target: "dev", agent: AgentState(state: "current")))
        XCTAssertEqual(PlanLogic.agentWarning(target: "dev", agent: AgentState(state: "lockdown"))?.1, .danger)
    }

    func testFormats() {
        let summer = Format.parse("2026-07-01T12:32:05.123456+00:00")!
        XCTAssertEqual(Format.time(summer), "14:32")  // CEST
        XCTAssertEqual(Format.timeSeconds(summer), "14:32:05")
        let winter = Format.parse("2026-12-01T12:32:05+00:00")!
        XCTAssertEqual(Format.exact(winter), "01.12.2026 13:32")  // CET
        XCTAssertEqual(Format.duration(72), "1 min 12 s")
        XCTAssertEqual(Format.duration(4.4), "4 s")
        XCTAssertEqual(Format.countdown(20 * 60 + 32), "20:32")
        XCTAssertEqual(Format.countdown(-1), "00:00")
        XCTAssertEqual(Format.bytes(1_048_576), "1 MB")
        XCTAssertEqual(Format.bytes(3 * 1_073_741_824 / 2), "1.5 GB")
        XCTAssertEqual(Format.shortHash("sha256:8f3e1c2d5b6a7e8f9a0b1c2d3e4fa1d0"), "sha256:8f3e…a1d0")
        let now = Date()
        XCTAssertEqual(Format.relative(now.addingTimeInterval(-90), now: now), "1 min ago")
        XCTAssertEqual(Format.relative(now.addingTimeInterval(-90), now: now, L("da")), "for 1 min siden")
    }

    func testCronInPlainLanguage() {
        XCTAssertEqual(CronText.describe("0 3 * * *"), "Every day at 03:00")
        XCTAssertEqual(CronText.describe("0 6 * * 1"), "Every Monday at 06:00")
        XCTAssertEqual(CronText.describe("0 6 * * 1", L("da")), "Hver mandag kl. 06:00")
        XCTAssertEqual(CronText.describe("*/15 * * * *"), "Every 15 minutes")
        XCTAssertEqual(CronText.describe("5 4 1,15 * *"), "5 4 1,15 * *")
    }

    func testANSI() {
        let spans = ANSI.spans("\u{1b}[1;31mERR\u{1b}[0m ok \u{1b}]0;title\u{07}x")
        XCTAssertEqual(spans.first, ANSISpan(text: "ERR", colour: .danger, bold: true))
        XCTAssertEqual(ANSI.strip("\u{1b}[32m✓ passed\u{1b}[0m\nnext"), "✓ passed\nnext")
        XCTAssertFalse(ANSI.spans("a\u{1b}[2Kb").map(\.text).joined().contains("\u{1b}"))
    }

    func testPairingLink() {
        let p = PairingLink(" https://warden.example.dk/register?token=9BhmlkHWCOqiTHr9kO01zUHc5Hx_fmhB\n")
        XCTAssertEqual(p?.server.absoluteString, "https://warden.example.dk")
        XCTAssertEqual(p?.token, "9BhmlkHWCOqiTHr9kO01zUHc5Hx_fmhB")
        XCTAssertNil(PairingLink("http://warden.lan/register?token=9BhmlkHWCOqiTHr9kO01zUHc5Hx_fmhB"))  // not https
        XCTAssertNil(PairingLink("https://warden.example.dk/elsewhere?token=9BhmlkHWCOqiTHr9kO01zUHc5Hx_fmhB"))
        XCTAssertNil(PairingLink("https://warden.example.dk/register?token=short"))
        XCTAssertNil(PairingLink("https://warden.example.dk/register?token=9BhmlkHWCOqiTHr9kO01zUHc5Hx%22%3E"))
    }

    func testRequestsCarryOriginAndCSRFHeaderAndMapErrors() async throws {
        let fake = Fake([(200, try Fixtures.raw("api_examples.json", key: "status")), (401, Data()), (503, Data())])
        let api = APIClient(server: URL(string: "https://warden.example.dk")!, transport: fake)!
        _ = try await api.status()
        let r = fake.requests[0]
        XCTAssertEqual(r.url?.absoluteString, "https://warden.example.dk/api/status")
        XCTAssertEqual(r.value(forHTTPHeaderField: "Origin"), "https://warden.example.dk")
        XCTAssertEqual(r.value(forHTTPHeaderField: "X-Warden"), "1")
        await XCTAssertThrowsErrorAsync(try await api.status(), APIError.signedOut)
        await XCTAssertThrowsErrorAsync(try await api.status(), APIError.offline)
        fake.fail = true
        await XCTAssertThrowsErrorAsync(try await api.status(), APIError.offline)
        _ = try? await api.feed()
        XCTAssertEqual(fake.requests.last?.url?.absoluteString, "https://warden.example.dk/api/feed?limit=100")
    }
}

func XCTAssertThrowsErrorAsync(_ expr: @autoclosure () async throws -> some Any, _ expected: APIError, file: StaticString = #filePath, line: UInt = #line) async {
    do {
        _ = try await expr()
        XCTFail("no error", file: file, line: line)
    } catch {
        XCTAssertEqual(error as? APIError, expected, file: file, line: line)
    }
}

final class SettingsTests: XCTestCase {
    func testNotificationPrefsRoundTrip() async throws {
        let body = Data(#"{"values": {"notifications.approval_needed": true, "notifications.plan_failed": false, "ui.language": "da"}}"#.utf8)
        let fake = Fake([(200, body), (200, body)])
        let api = APIClient(server: URL(string: "https://warden.example.dk")!, transport: fake)!
        let prefs = try await api.notificationPrefs()
        XCTAssertEqual(prefs.values, ["approval_needed": true, "plan_failed": false])
        _ = try await api.setNotification("plan_failed", true)
        let sent = String(decoding: fake.requests[1].httpBody ?? Data(), as: UTF8.self)
        XCTAssertEqual(fake.requests[1].httpMethod, "PUT")
        XCTAssertEqual(sent, #"{"changes":{"notifications.plan_failed":true}}"#)
    }
}

/// Every string the app shows through `.t("…")` has a Danish entry (README 17.2).
final class L10nTests: XCTestCase {
    func testEveryAppStringHasDanish() throws {
        let ios = Fixtures.root.appendingPathComponent("ios")
        var missing: [String] = []
        let regex = try NSRegularExpression(pattern: #"\.t\("((?:[^"\\]|\\.)*)""#)
        for dir in ["Sources", "Packages/WardenCore/Sources"] {
            let base = ios.appendingPathComponent(dir)
            guard let walker = FileManager.default.enumerator(at: base, includingPropertiesForKeys: nil) else { continue }
            for case let url as URL in walker where url.pathExtension == "swift" {
                let text = try String(contentsOf: url, encoding: .utf8)
                for m in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
                    let key = String(text[Range(m.range(at: 1), in: text)!]).replacingOccurrences(of: "\\\"", with: "\"")
                    if Danish.table[key] == nil { missing.append(key) }
                }
            }
        }
        XCTAssertEqual(Set(missing), [], "add these to ios/danish-app.json and run scripts/gen-danish.py")
    }
}
