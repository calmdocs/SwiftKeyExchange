//
//  Curve25519.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 22/8/2023.
//

import Foundation
import CryptoKit

/// Create a Curve25519 eliptic curve public key.
/// - Parameter key: The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) private key.
/// - Throws: KeyExchangeError.invalidKey.
/// - Returns: The public key Data.
public func Curve25519PublicStore(_ key: String) throws -> Curve25519.KeyAgreement.PublicKey {
    if key == "" {
        throw KeyExchangeError.invalidKey
    }
    guard let b = Data(base64Encoded: key) else {
        throw KeyExchangeError.invalidKey
    }
    return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: b)
}

/// Create a Curve25519 eliptic curve private key.
/// - Returns: The private key Data.
public func Curve25519PrivateStore() -> Curve25519.KeyAgreement.PrivateKey {
    return Curve25519.KeyAgreement.PrivateKey()
}

/// Create a Curve25519 eliptic curve private key from the provided private key String. Only use a specified (i.e. non-random) private keys for testing.
/// - Parameter key: The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) private key.  Set as an empty String to create a random private key.
/// - Throws: KeyExchangeError.invalidKey.
/// - Returns: The private key Data.
public func Curve25519PrivateStore(_ key: String) throws -> Curve25519.KeyAgreement.PrivateKey {
    if key == "" {
        return Curve25519.KeyAgreement.PrivateKey()
    }
    guard let b = Data(base64Encoded: key) else {
        throw KeyExchangeError.invalidKey
    }
    return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: b)
}

public extension Curve25519.KeyAgreement.PrivateKey {
    
    /// Create a SharedSecret from a Curve25519.KeyAgreement.PublicKey
    /// - Parameter key: The Curve25519.KeyAgreement.PublicKey.
    /// - Returns: The SharedSecret Data.
    func sharedSecretFromKeyAgreementData(_ key: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try self.sharedSecretFromKeyAgreement(with: key)
        return sharedSecret.withUnsafeBytes { return Data(Array($0)) }
    }
}
