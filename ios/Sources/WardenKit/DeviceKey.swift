import Foundation
import LocalAuthentication
import Security
import WardenCore

/// The Face ID device key (DECISIONS M8-01): a P-256 key created in the Secure Enclave, usable only after
/// Face ID with the currently enrolled faces (`.biometryCurrentSet`), and never exportable. Warden knows it
/// as an approver like any passkey; agents verify its signatures themselves.
///
/// The keychain item has no explicit access group, so it lands in the first group of the entitlements
/// (`<Team ID>.dk.schwabejss.warden`), which the app and the notification extension share.
public final class DeviceKey: DeviceSigner, @unchecked Sendable {
    static let tag = Data("dk.schwabejss.warden.devicekey".utf8)

    let key: SecKey
    let context: LAContext
    public let publicKeyX963: Data

    init(key: SecKey, context: LAContext) throws {
        self.key = key
        self.context = context
        guard let pub = SecKeyCopyPublicKey(key), let raw = SecKeyCopyExternalRepresentation(pub, nil) as Data? else {
            throw DeviceKeyError.noPublicKey
        }
        publicKeyX963 = raw
    }

    /// The key, if this iPhone was paired. `reason` is what Face ID shows; one context means one Face ID
    /// for every signature made with this instance (sign-in and approval together).
    public static func load(reason: String) throws -> DeviceKey? {
        let context = LAContext()
        context.localizedReason = reason
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let item else { throw DeviceKeyError.keychain(status) }
        return try DeviceKey(key: item as! SecKey, context: context)  // swiftlint:disable:this force_cast
    }

    /// Make a new key (pairing). Any old one is removed first.
    public static func create(reason: String) throws -> DeviceKey {
        remove()
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &error
        ) else { throw DeviceKeyError.create(error?.takeRetainedValue().localizedDescription ?? "access control") }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw DeviceKeyError.create(error?.takeRetainedValue().localizedDescription ?? "Secure Enclave")
        }
        let context = LAContext()
        context.localizedReason = reason
        return try DeviceKey(key: key, context: context)
    }

    public static func remove() {
        let query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag]
        SecItemDelete(query as CFDictionary)
    }

    public func sign(_ data: Data) async throws -> Data {
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data? else {
            let e = error?.takeRetainedValue()
            if let e, CFErrorGetCode(e) == LAError.userCancel.rawValue { throw DeviceKeyError.cancelled }
            throw DeviceKeyError.sign(e?.localizedDescription ?? "Face ID")
        }
        return sig
    }
}

public enum DeviceKeyError: Error, LocalizedError {
    case noPublicKey, cancelled
    case keychain(OSStatus)
    case create(String), sign(String)

    public var errorDescription: String? {
        switch self {
        case .noPublicKey: return "The device key has no public key."
        case .cancelled: return "Face ID was cancelled. Nothing was sent."
        case .keychain(let s): return "Keychain error \(s)."
        case .create(let m), .sign(let m): return m
        }
    }
}
