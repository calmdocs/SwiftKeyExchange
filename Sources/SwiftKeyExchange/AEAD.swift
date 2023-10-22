//
//  AEAD.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 22/8/2023.
//

import Foundation
import CryptoKit

/// Random nonce for the provided type of authenticated encryption with associated data (AEAD).
/// - Parameter aead: The Authenticated encryption with associated data (AEAD) type.
/// - Throws: KeyExchangeError.invalidAEAD
/// - Returns: The nonce Data.
public func AEADRandomNonce(_ aead: KeyExchangeAEAD) throws -> Data {
    var nonce: Data
    switch aead {
    case .aesgcm:
        nonce = KeyExchangeRandomBytes(12)
    case .chachapoly:
        nonce = KeyExchangeRandomBytes(12)
    default:
        throw KeyExchangeError.invalidAEAD
    }
    return nonce
}

/// Random key for the provided type of authenticated encryption with associated data (AEAD).
/// - Parameter aead: The Authenticated encryption with associated data (AEAD) type.
/// - Throws: KeyExchangeError.invalidAEAD.
/// - Returns: The key Data.
public func AEADRandomKey(_ aead: KeyExchangeAEAD) throws -> Data {
    var nonce: Data
    switch aead {
    case .aesgcm:
        nonce = KeyExchangeRandomBytes(32)
    case .chachapoly:
        nonce = KeyExchangeRandomBytes(32)
    default:
        throw KeyExchangeError.invalidAEAD
    }
    return nonce
}

/// Authenticated encryption with associated data (AEAD) encrypt.
/// - Parameters:
///   - aead: The Authenticated encryption with associated data (AEAD) type.
///   - symmetricKey: The SymmetricKey used to encrypt the Data.
///   - plaintext: The plain text data to encrypt.
///   - aeadNonce: The nonce data.
///   - additionalData: The additionalData (which does not need to be secret) used when encrypting
/// - Throws: KeyExchangeError.invalidAEAD.
/// - Returns: The cyphertext string.
public func AEADEncrypt(
    aead: KeyExchangeAEAD,
    symmetricKey: SymmetricKey,
    plaintext: any DataProtocol,
    aeadNonce: Data,
    additionalData: Data
) throws -> String {
    var ciphertext: String
    switch aead {
    case .aesgcm:
        let sealedBox = try AESGCMEncrypt(
            symmetricKey: symmetricKey,
            message: plaintext,
            nonce: try AES.GCM.Nonce(data: aeadNonce),
            additionalData: additionalData
        )
        ciphertext = sealedBox.combined!.base64EncodedString()
    case .chachapoly:
        let sealedBox = try ChaChaPolyEncrypt(
            symmetricKey: symmetricKey,
            message: plaintext,
            nonce: try ChaChaPoly.Nonce(data: aeadNonce),
            additionalData: additionalData
        )
        ciphertext = sealedBox.combined.base64EncodedString()
    default:
        throw KeyExchangeError.invalidAEAD
    }
    return ciphertext
}

/// Authenticated encryption with associated data (AEAD) decrypt.
/// - Parameters:
///   - aead: The Authenticated encryption with associated data (AEAD) type.
///   - symmetricKey: The SymmetricKey used to encrypt the Data.
///   - ciphertext: The encrypted data to decrypt.
///   - aeadNonce: The nonce data.
///   - additionalData: The additionalData (which does not need to be secret) used when encrypting.
/// - Throws: KeyExchangeError.invalidAEAD.
/// - Returns: The decrypted plaintext.
public func AEADDecrypt(
    aead: KeyExchangeAEAD,
    symmetricKey: SymmetricKey,
    ciphertext: String,
    aeadNonce: String,
    additionalData: String
) throws -> Data {
    var plaintext: Data
    switch aead {
    case .aesgcm:
        plaintext = try AESGCMDecrypt(
            symmetricKey: symmetricKey,
            combined: Data(base64Encoded: ciphertext)!,
            additionalData: Data(base64Encoded: additionalData)!
        )
    case .chachapoly:
        plaintext = try ChaChaPolyDecrypt(
            symmetricKey: symmetricKey,
            combined: Data(base64Encoded: ciphertext)!,
            additionalData: Data(base64Encoded: additionalData)!
        )
    default:
        throw KeyExchangeError.invalidAEAD
    }
    return plaintext
}
