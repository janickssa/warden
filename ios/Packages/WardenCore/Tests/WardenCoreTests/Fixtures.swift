import Foundation

/// The repo's shared fixtures (policy-fixtures/), found from this file's path.
enum Fixtures {
    static var root: URL {
        URL(fileURLWithPath: #filePath)  // ios/Packages/WardenCore/Tests/WardenCoreTests/Fixtures.swift
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    }

    static func json(_ name: String) throws -> [String: Any] {
        let data = try Data(contentsOf: root.appendingPathComponent("policy-fixtures").appendingPathComponent(name))
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }

    static func raw(_ name: String, key: String) throws -> Data {
        let all = try json(name)
        return try JSONSerialization.data(withJSONObject: all[key]!)
    }
}
