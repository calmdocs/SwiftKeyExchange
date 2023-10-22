//
//  ChaChaPoly.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 23/8/2023.
//

import Foundation
import CryptoKit

/// Encrypt using the ChaCha20 stream cipher with the Poly1305 message authentication code.
/// - Parameters:
///   - symmetricKey: The SymmetricKey used to encrypt the Data.
///   - message: The plain text data to encrypt.
///   - nonce: The nonce data.
///   - additionalData: The additionalData (which does not need to be secret) used when encrypting.
/// - Throws: A KeyExchangeError.
/// - Returns: A ChaChaPoly.SealedBox.
public func ChaChaPolyEncrypt(
    symmetricKey: SymmetricKey,
    message: any DataProtocol,
    nonce: ChaChaPoly.Nonce,
    additionalData: any DataProtocol
) throws -> ChaChaPoly.SealedBox {
    return try ChaChaPoly.seal(
        message,
        using: symmetricKey,
        nonce: nonce,
        authenticating: additionalData
    )
}

/// Decrypt using the ChaCha20 stream cipher with the Poly1305 message authentication code.
/// - Parameters:
///   - symmetricKey: The SymmetricKey used to encrypt the Data.
///   - combined: The encrypted ciphertext.
///   - additionalData: The additionalData (which does not need to be secret) used when encrypting.
/// - Throws: a KeyExchangeError.
/// - Returns: The decrypted Data.
public func ChaChaPolyDecrypt(
    symmetricKey: SymmetricKey,
    combined: any DataProtocol,
    additionalData: any DataProtocol
) throws -> Data {
    let sealedBox = try ChaChaPoly.SealedBox(combined: combined)
    return try ChaChaPoly.open(
        sealedBox,
        using: symmetricKey,
        authenticating: additionalData
    )
}
