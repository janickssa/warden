import Crypto
import Foundation

/// Signs with the Face ID device key. The app's implementation is a Secure Enclave P-256 key that only
/// signs after Face ID; tests use a software key.
public protocol DeviceSigner: Sendable {
    /// Uncompressed public key: 0x04 || x || y (65 bytes).
    var publicKeyX963: Data { get }
    /// DER ECDSA-SHA256 signature over `data`.
    func sign(_ data: Data) async throws -> Data
}

/// The relying party Warden expects: its public URL's host and origin (README 10.0, DECISIONS M8-01).
public struct RelyingParty: Equatable, Sendable {
    public let rpID: String
    public let origin: String

    public init(rpID: String, origin: String) {
        self.rpID = rpID
        self.origin = origin
    }

    /// From the server URL, as Warden derives it from `server.public_url`.
    public init?(serverURL: URL) {
        guard let scheme = serverURL.scheme?.lowercased(), let host = serverURL.host?.lowercased(),
              scheme == "https" || (scheme == "http" && (host == "localhost" || host == "127.0.0.1"))
        else { return nil }
        rpID = host
        origin = serverURL.port.map { "\(scheme)://\(host):\($0)" } ?? "\(scheme)://\(host)"
    }
}

/// What the API takes as `credential`, as a browser would send it.
public struct WebAuthnCredential: Codable, Equatable, Sendable {
    public struct Response: Codable, Equatable, Sendable {
        public var clientDataJSON: String
        public var attestationObject: String?
        public var authenticatorData: String?
        public var signature: String?
        public var userHandle: String?
    }

    public var id: String
    public var rawId: String
    public var type: String = "public-key"
    public var response: Response
    public var clientExtensionResults: [String: String] = [:]
}

public enum WebAuthnError: Error, Equatable {
    case badPublicKey
    case unsafeClientData
}

/// The Face ID device key's WebAuthn messages (DECISIONS M8-01): fixed layout, counter always 0, UP|UV.
public struct DeviceAuthenticator: Sendable {
    public static let up: UInt8 = 0x01
    public static let uv: UInt8 = 0x04
    public static let at: UInt8 = 0x40

    public let rp: RelyingParty
    public let signer: DeviceSigner

    public init(rp: RelyingParty, signer: DeviceSigner) {
        self.rp = rp
        self.signer = signer
    }

    var xy: (Data, Data) {
        let k = signer.publicKeyX963
        return (k.subdata(in: 1..<33), k.subdata(in: 33..<65))
    }

    /// The first 16 bytes of SHA-256 over the uncompressed public key.
    public var credentialID: Data { Data(SHA256.hash(data: signer.publicKeyX963)).prefix(16) }
    public var credentialIDString: String { Base64URL.encode(credentialID) }

    public var cose: Data {
        let (x, y) = xy
        return CBOR.map([
            (.int(1), .int(2)), (.int(3), .int(-7)), (.int(-1), .int(1)), (.int(-2), .bytes(x)), (.int(-3), .bytes(y)),
        ]).encoded
    }

    var rpHash: Data { Data(SHA256.hash(data: Data(rp.rpID.utf8))) }

    public static func clientData(type: String, challenge: String, origin: String) throws -> Data {
        for s in [challenge, origin] where s.contains("\"") || s.contains("\\") || s.unicodeScalars.contains(where: { $0.value < 0x20 }) {
            throw WebAuthnError.unsafeClientData
        }
        return Data(#"{"type":"\#(type)","challenge":"\#(challenge)","origin":"\#(origin)","crossOrigin":false}"#.utf8)
    }

    /// (attestationObject, clientDataJSON) for `navigator.credentials.create`-style registration.
    public func registration(challenge: String) throws -> (Data, Data) {
        guard signer.publicKeyX963.count == 65, signer.publicKeyX963.first == 0x04 else { throw WebAuthnError.badPublicKey }
        let attested = Data(count: 16) + Data([0, 16]) + credentialID + cose
        let auth = rpHash + Data([Self.up | Self.uv | Self.at]) + Data(count: 4) + attested
        let att = CBOR.map([
            (.text("fmt"), .text("none")),
            (.text("attStmt"), .map([])),
            (.text("authData"), .bytes(auth)),
        ]).encoded
        return (att, try Self.clientData(type: "webauthn.create", challenge: challenge, origin: rp.origin))
    }

    /// (authenticatorData, clientDataJSON) for an assertion; sign `authData || SHA-256(clientDataJSON)`.
    public func assertionParts(challenge: String) throws -> (Data, Data) {
        (rpHash + Data([Self.up | Self.uv]) + Data(count: 4),
         try Self.clientData(type: "webauthn.get", challenge: challenge, origin: rp.origin))
    }

    public func create(challenge: String) throws -> WebAuthnCredential {
        let (att, cdj) = try registration(challenge: challenge)
        let id = credentialIDString
        return WebAuthnCredential(
            id: id, rawId: id,
            response: .init(clientDataJSON: Base64URL.encode(cdj), attestationObject: Base64URL.encode(att))
        )
    }

    /// One Face ID: the signer asks for it.
    public func get(challenge: String) async throws -> WebAuthnCredential {
        let (auth, cdj) = try assertionParts(challenge: challenge)
        let sig = try await signer.sign(auth + Data(SHA256.hash(data: cdj)))
        let id = credentialIDString
        return WebAuthnCredential(
            id: id, rawId: id,
            response: .init(
                clientDataJSON: Base64URL.encode(cdj), authenticatorData: Base64URL.encode(auth),
                signature: Base64URL.encode(sig), userHandle: nil
            )
        )
    }
}

/// A software P-256 signer for tests (and nothing else: the app uses the Secure Enclave).
public struct SoftwareSigner: DeviceSigner {
    let key: P256.Signing.PrivateKey

    public init(rawScalar: Data) throws { key = try P256.Signing.PrivateKey(rawRepresentation: rawScalar) }
    public init() { key = P256.Signing.PrivateKey() }

    public var publicKeyX963: Data { key.publicKey.x963Representation }

    public func sign(_ data: Data) async throws -> Data { try key.signature(for: data).derRepresentation }
}
