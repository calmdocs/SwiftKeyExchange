//
//  Curve.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 22/8/2023.
//

import Foundation
import CryptoKit

/// Create an elliptic-curve cryptography (ECC) private key and public key.
/// - Parameters:
///   - curve: The KeyExchangeCurve (Elliptic-curve cryptography (ECC)).
///   - privateKey: The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) private key.
/// - Throws: KeyExchangeError.invalidCurve
/// - Returns: KeyExchangeLocalKeys (containing var privateKey and publicKey Strings).
public func KeyExchangeCurveKeys(
    curve: KeyExchangeCurve,
    privateKey: String
) throws -> KeyExchangeLocalKeys {
    var localPrivateKey: String
    var localPublicKey: String
    switch curve {
    case .curve25519:
        let privateStore = try Curve25519PrivateStore(privateKey)
        localPrivateKey = privateStore.rawRepresentation.base64EncodedString()
        localPublicKey = privateStore.publicKey.rawRepresentation.base64EncodedString()
    case .p256:
        let privateStore = try P256PrivateStore(privateKey)
        localPrivateKey = privateStore.rawRepresentation.base64EncodedString()
        localPublicKey = privateStore.publicKey.rawRepresentation.base64EncodedString()
    case .p384:
        let privateStore = try P384PrivateStore(privateKey)
        localPrivateKey = privateStore.rawRepresentation.base64EncodedString()
        localPublicKey = privateStore.publicKey.rawRepresentation.base64EncodedString()
    case .p521:
        let privateStore = try P521PrivateStore(privateKey)
        localPrivateKey = privateStore.rawRepresentation.base64EncodedString()
        localPublicKey = privateStore.publicKey.rawRepresentation.base64EncodedString()
    default:
        throw KeyExchangeError.invalidCurve
    }
    return KeyExchangeLocalKeys(
        privateKey: localPrivateKey,
        publicKey: localPublicKey
    )
}
