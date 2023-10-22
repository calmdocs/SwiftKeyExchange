//
//  AESGCM.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 23/8/2023.
//

import Foundation
import CryptoKit

/// Encrypt using Advanced Encryption Standard (AES) Galois/Counter Mode (GCM).
/// - Parameters:
///   - symmetricKey: The SymmetricKey used to encrypt the Data.
///   - message: The plain text data to encrypt.
///   - nonce: The nonce data.
///   - additionalData: The additionalData (which does not need to be secret) used when encrypting.
/// - Throws: A KeyExchangeError.
/// - Returns: A AES.GCM.SealedBox.
public func AESGCMEncrypt(
    symmetricKey: SymmetricKey,
    message: any DataProtocol,
    nonce: AES.GCM.Nonce,
    additionalData: any DataProtocol
) throws -> AES.GCM.SealedBox {
    return try AES.GCM.seal(
        message,
        using: symmetricKey,
        nonce: nonce,
        authenticating: additionalData
    )
}

/// Decrypt using Advanced Encryption Standard (AES) Galois/Counter Mode (GCM).
/// - Parameters:
///   - symmetricKey: The SymmetricKey used to encrypt the Data.
///   - combined: The encrypted ciphertext.
///   - additionalData: The additionalData (which does not need to be secret) used when encrypting.
/// - Throws: a KeyExchangeError.
/// - Returns: The decrypted Data.
public func AESGCMDecrypt(
    symmetricKey: SymmetricKey,
    combined: any DataProtocol,         // nonce + cyphertext + additionalData
    additionalData: any DataProtocol
) throws -> Data {
    let sealedBox = try AES.GCM.SealedBox(combined: combined)
    return try AES.GCM.open(
        sealedBox,
        using: symmetricKey,
        authenticating: additionalData
    )
}
