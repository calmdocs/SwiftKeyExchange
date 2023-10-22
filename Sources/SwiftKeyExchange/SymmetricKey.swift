//
//  SymmetricKey.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 22/8/2023.
//

import Foundation
import CryptoKit

public extension SymmetricKey {
    
    /// Get the SymmetricKey Data
    /// - Returns: The SymmetricKeyData.
    func data() -> Data {
        return self.withUnsafeBytes { return Data(Array($0)) }
    }
}

/// Create a SymmetricKey
/// - Parameters:
///   - sharedSecret: The SharedSecret.
///   - hashFunction: The HashFunction.
///   - kdf: The KeyExchangeKDF (Key derivation function (KDF)).
///   - nonce: The nonce.
///   - additionalData: The additionalData bytes (which do not need to be secret) used to create the SymmetricKey.
/// - Throws: KeyExchangeError.invalidKDF
/// - Returns: The SymmetricKey.
public func KeyExchangeSymmetricKey<H>(
    sharedSecret: SharedSecret,
    using hashFunction: H.Type,
    kdf: KeyExchangeKDF,
    nonce: any DataProtocol,
    additionalData: any DataProtocol
) throws -> SymmetricKey where H : HashFunction {
    var symmetricKey: SymmetricKey
    switch kdf {
    case .hkdf:
        symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: hashFunction,
            salt: nonce,
            sharedInfo: additionalData,
            outputByteCount: hashFunction.Digest.byteCount
        )
    default:
        throw KeyExchangeError.invalidKDF
    }
    return symmetricKey
}
