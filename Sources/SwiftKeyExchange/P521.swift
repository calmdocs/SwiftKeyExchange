//
//  P521.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 22/8/2023.
//

import Foundation
import CryptoKit

/// Create a P521 eliptic curve public key.
/// - Parameter key: The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) private key.
/// - Throws: KeyExchangeError.invalidKey.
/// - Returns: The public key Data.
public func P521PublicStore(_ key: String) throws -> P521.KeyAgreement.PublicKey {
    if key == "" {
        throw KeyExchangeError.invalidKey
    }
    guard let b = Data(base64Encoded: key) else {
        throw KeyExchangeError.invalidKey
    }
    return try P521.KeyAgreement.PublicKey(rawRepresentation: b)
}

/// Create a P521 eliptic curve private key.
/// - Returns: The private key Data.
public func P521PrivateStore() -> P521.KeyAgreement.PrivateKey {
    return P521.KeyAgreement.PrivateKey()
}

/// Create a P521 eliptic curve private key from the provided private key String. Only use a specified (i.e. non-random) private keys for testing.
/// - Parameter key: The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) private key.  Set as an empty String to create a random private key.
/// - Throws: KeyExchangeError.invalidKey.
/// - Returns: The private key Data.
public func P521PrivateStore(_ key: String) throws -> P521.KeyAgreement.PrivateKey {
    if key == "" {
        return P521.KeyAgreement.PrivateKey()
    }
    guard let b = Data(base64Encoded: key) else {
        throw KeyExchangeError.invalidKey
    }
    return try P521.KeyAgreement.PrivateKey(rawRepresentation: b)
}

public extension P521.KeyAgreement.PrivateKey {
    
    /// Create a SharedSecret from a P521.KeyAgreement.PublicKey
    /// - Parameter key: The P521.KeyAgreement.PublicKey.
    /// - Returns: The SharedSecret Data.
    func sharedSecretFromKeyAgreementData(_ key: P521.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try self.sharedSecretFromKeyAgreement(with: key)
        return sharedSecret.withUnsafeBytes { return Data(Array($0)) }
    }
}
