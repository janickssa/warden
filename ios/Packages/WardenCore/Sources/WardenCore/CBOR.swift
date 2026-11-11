import Foundation

/// The little CBOR WebAuthn needs: ints, byte and text strings, and maps whose pairs the caller gives in
/// canonical order. Byte-for-byte the same as backend/tests/devicekey.py.
public enum CBOR {
    case int(Int)
    case bytes(Data)
    case text(String)
    case map([(CBOR, CBOR)])

    public var encoded: Data {
        switch self {
        case .int(let n): return n >= 0 ? Self.head(0, UInt64(n)) : Self.head(1, UInt64(-1 - n))
        case .bytes(let d): return Self.head(2, UInt64(d.count)) + d
        case .text(let t):
            let raw = Data(t.utf8)
            return Self.head(3, UInt64(raw.count)) + raw
        case .map(let pairs):
            var out = Self.head(5, UInt64(pairs.count))
            for (k, v) in pairs { out += k.encoded + v.encoded }
            return out
        }
    }

    static func head(_ major: UInt8, _ n: UInt64) -> Data {
        let m = major << 5
        switch n {
        case 0..<24: return Data([m | UInt8(n)])
        case 24..<256: return Data([m | 24, UInt8(n)])
        case 256..<65536: return Data([m | 25, UInt8(n >> 8), UInt8(n & 0xff)])
        default: return Data([m | 26, UInt8(n >> 24 & 0xff), UInt8(n >> 16 & 0xff), UInt8(n >> 8 & 0xff), UInt8(n & 0xff)])
        }
    }
}
