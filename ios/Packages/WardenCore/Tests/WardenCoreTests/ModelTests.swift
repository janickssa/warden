import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import XCTest
@testable import WardenCore

/// Every real API response in policy-fixtures/api_examples.json (backend/tests/test_api_examples.py) decodes.
final class ModelTests: XCTestCase {
    func decode<T: Decodable>(_ key: String, as: T.Type) throws -> T {
        try WardenJSON.decoder.decode(T.self, from: Fixtures.raw("api_examples.json", key: key))
    }

    func testEveryExampleDecodes() throws {
        let status = try decode("status", as: StatusView.self)
        XCTAssertFalse(status.lockdown)
        XCTAssertEqual(status.language, "en")
        _ = try decode("me", as: Me.self)
        let approvals = try decode("approvals", as: PlanList.self)
        XCTAssertFalse(approvals.plans.isEmpty)
        _ = try decode("plans", as: PlanList.self)
        let waiting = try decode("plan_waiting", as: PlanDetail.self)
        XCTAssertEqual(waiting.status, "awaiting_approval")
        XCTAssertEqual(waiting.stepList.map(\.command), ["npm ci", "npm test"])
        let done = try decode("plan_succeeded", as: PlanDetail.self)
        XCTAssertEqual(done.stepList.first?.durationS, 1.5)
        XCTAssertNotNil(done.approval)
        _ = try decode("output", as: OutputView.self)
        let opts = try decode("approval_options", as: ApproveOptions.self)
        XCTAssertNotNil(opts.challenge?.challenge)
        let login = try decode("login_options", as: ChallengeOptions.self)
        XCTAssertNotNil(login.challenge)
        XCTAssertFalse(try decode("feed", as: Feed.self).items.isEmpty)
        XCTAssertEqual(try decode("schedules", as: [ScheduleView].self).first?.name, "nightly")
        XCTAssertEqual(try decode("schedule", as: ScheduleDetail.self).stepList.count, 1)
        _ = try decode("devices", as: [DeviceView].self)
    }

    func testErrorsCarryWardensReason() async throws {
        let problem = try Fixtures.raw("api_examples.json", key: "problem")
        let client = APIClient(server: URL(string: "https://warden.example.dk")!, transport: Fake([(400, problem)]))!
        do {
            _ = try await client.approve("pln_x", hash: "sha256:00", signed: nil)
            XCTFail("no error")
        } catch let APIError.refused(status, code, _) {
            XCTAssertEqual(status, 400)
            XCTAssertEqual(code, "hash_prefix")
        }
    }
}

final class Fake: Transport, @unchecked Sendable {
    var replies: [(Int, Data)]
    var requests: [URLRequest] = []
    var fail = false

    init(_ replies: [(Int, Data)] = []) { self.replies = replies }

    func send(_ request: URLRequest) async throws -> (Data, Int) {
        requests.append(request)
        if fail { throw URLError(.notConnectedToInternet) }
        if replies.isEmpty { return (Data("{}".utf8), 200) }
        let (status, body) = replies.removeFirst()
        return (body, status)
    }
}
