//
//  SharedSecret.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 22/8/2023.
//

import Foundation
import CryptoKit

public extension SharedSecret {
    
    /// Get the SharedSecret Data
    /// - Returns: The SharedSecret Data.
    func data() -> Data {
        return self.withUnsafeBytes { return Data(Array($0)) }
    }
}

/// Create a SharedSecret
/// - Parameters:
///   - curve: The KeyExchangeCurve (Elliptic-curve cryptography (ECC)).
///   - privateKey: The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) private key.
///   - privateKey: The external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
/// - Throws: KeyExchangeError.invalidCurve.
/// - Returns: The SharedSecret.
public func CreateSharedSecret(
    curve: KeyExchangeCurve,
    privateKey: String,
    publicKey: String
) throws -> SharedSecret {
    var sharedSecret: SharedSecret
    switch curve {
    case .curve25519:
        let privateStore = try Curve25519PrivateStore(privateKey)
        let publicStore = try Curve25519PublicStore(publicKey)
        sharedSecret = try privateStore.sharedSecretFromKeyAgreement(with: publicStore)
    case .p256:
        let privateStore = try P256PrivateStore(privateKey)
        let publicStore = try P256PublicStore(publicKey)
        sharedSecret = try privateStore.sharedSecretFromKeyAgreement(with: publicStore)
    case .p384:
        let privateStore = try P384PrivateStore(privateKey)
        let publicStore = try P384PublicStore(publicKey)
        sharedSecret = try privateStore.sharedSecretFromKeyAgreement(with: publicStore)
    case .p521:
        let privateStore = try P521PrivateStore(privateKey)
        let publicStore = try P521PublicStore(publicKey)
        sharedSecret = try privateStore.sharedSecretFromKeyAgreement(with: publicStore)
    default:
        throw KeyExchangeError.invalidCurve
    }
    return sharedSecret
}
