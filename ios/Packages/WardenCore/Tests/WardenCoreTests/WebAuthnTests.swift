import Crypto
import Foundation
import XCTest
@testable import WardenCore

/// The Face ID device key's WebAuthn bytes must equal what Python pinned and py_webauthn and the Go agent
/// accept (policy-fixtures/ios_webauthn_vectors.json, DECISIONS M8-01).
final class WebAuthnTests: XCTestCase {
    func vectors() throws -> [String: Any] { try Fixtures.json("ios_webauthn_vectors.json") }

    func authenticator(_ v: [String: Any]) throws -> DeviceAuthenticator {
        let signer = try SoftwareSigner(rawScalar: Data(hex: v["private_key_hex"] as! String)!)
        return DeviceAuthenticator(rp: RelyingParty(rpID: v["rp_id"] as! String, origin: v["origin"] as! String), signer: signer)
    }

    func testRegistrationBytesMatchPython() throws {
        let v = try vectors()
        let a = try authenticator(v)
        XCTAssertEqual(a.signer.publicKeyX963.hex, v["public_x963_hex"] as! String)
        XCTAssertEqual(a.credentialIDString, v["credential_id"] as! String)
        XCTAssertEqual(a.cose.hex, v["cose_hex"] as! String)
        let reg = v["registration"] as! [String: Any]
        let (att, cdj) = try a.registration(challenge: reg["challenge"] as! String)
        XCTAssertEqual(String(decoding: cdj, as: UTF8.self), reg["client_data_json"] as! String)
        XCTAssertEqual(att.hex, reg["attestation_object_hex"] as! String)
    }

    func testAssertionBytesMatchPythonAndSignaturesVerify() async throws {
        let v = try vectors()
        let a = try authenticator(v)
        let as_ = v["assertion"] as! [String: Any]
        let (auth, cdj) = try a.assertionParts(challenge: as_["challenge"] as! String)
        XCTAssertEqual(auth.hex, as_["authenticator_data_hex"] as! String)
        XCTAssertEqual(String(decoding: cdj, as: UTF8.self), as_["client_data_json"] as! String)
        // The challenge is SHA-256 of Warden's approval message.
        XCTAssertEqual(Base64URL.decode(as_["challenge"] as! String)!.hex, as_["message_sha256_hex"] as! String)

        let pub = try P256.Signing.PublicKey(x963Representation: a.signer.publicKeyX963)
        let signed = auth + Data(SHA256.hash(data: cdj))
        let pythons = try P256.Signing.ECDSASignature(derRepresentation: Base64URL.decode(as_["signature"] as! String)!)
        XCTAssertTrue(pub.isValidSignature(pythons, for: signed))
        let mine = try await a.get(challenge: as_["challenge"] as! String)
        let sig = try P256.Signing.ECDSASignature(derRepresentation: Base64URL.decode(mine.response.signature!)!)
        XCTAssertTrue(pub.isValidSignature(sig, for: signed))
        XCTAssertNil(mine.response.userHandle)
    }

    func testCredentialEncodesCamelCaseForTheAPI() async throws {
        let a = DeviceAuthenticator(rp: RelyingParty(rpID: "warden.example.dk", origin: "https://warden.example.dk"), signer: SoftwareSigner())
        let body = SignedChallenge(challengeId: "c1", credential: try await a.get(challenge: "abc"))
        let json = String(decoding: try WardenJSON.encoder.encode(body), as: UTF8.self)
        for key in ["\"challenge_id\":\"c1\"", "\"clientDataJSON\"", "\"authenticatorData\"", "\"rawId\"", "\"type\":\"public-key\""] {
            XCTAssertTrue(json.contains(key), key)
        }
    }

    func testRefusesUnsafeClientData() {
        XCTAssertThrowsError(try DeviceAuthenticator.clientData(type: "webauthn.get", challenge: "a\"b", origin: "https://x"))
    }

    func testRelyingPartyFromServerURL() {
        XCTAssertEqual(RelyingParty(serverURL: URL(string: "https://Warden.Example.dk/")!), RelyingParty(rpID: "warden.example.dk", origin: "https://warden.example.dk"))
        XCTAssertEqual(RelyingParty(serverURL: URL(string: "http://localhost:3900")!)?.origin, "http://localhost:3900")
        XCTAssertNil(RelyingParty(serverURL: URL(string: "http://warden.lan")!))  // passkeys need https
    }
}
