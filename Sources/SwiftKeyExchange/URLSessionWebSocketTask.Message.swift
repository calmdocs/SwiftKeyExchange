//
//  URLSessionWebSocketTask.Message.swift
//  SwiftKeyExchange
//  
//
//  Created by Iain McLaren on 16/9/2023.
//

import Foundation

/// Decrypts (i.e. performs the opposite of the Encrypt function) the ciphertext using the provided kdfNonce, ciphertext, aeadNonce, and additionalData.  All of this information is included in KeyExchangeAEADStore structs.
///
///  Then decode the decrypted data into the provided type.
///
/// - Parameters:
///   - message: The URLSessionWebSocketTask.Message
///   - kes: The KeyExchangeStore used to decrypt the data.
///   - auth: Function that validates whether the KeyExchangeStore additionalData is valid.
/// - Throws: KeyExchangeError.invalidFormat
/// - Returns: The decoded JSON.
public func KeyExchangeDecryptAndDecodeJSON<T: Decodable>(
    message: URLSessionWebSocketTask.Message,
    kes: KeyExchangeStore,
    auth: @escaping (String) throws -> Bool = { _ in return true }
) throws -> T {
    try _ = kes.ExternalPublicKey() // throws if no key
    switch message {
    case .string(let json):
        guard let data = json.data(using: .utf8) else {
            throw KeyExchangeError.invalidFormat
        }
        let aeadStore = try JSONDecoder().decode(KeyExchangeAEADStore.self, from: data)
        let decryptedData = try kes.decryptAEADStore(aeadStore)
        let message = try JSONDecoder().decode(T.self, from: decryptedData)
        if try !auth(aeadStore.additionalData) {
            throw KeyExchangeError.invalidAdditionalData
        }
        return message
    case .data:
        throw KeyExchangeError.invalidFormat
    @unknown default:
        throw KeyExchangeError.invalidFormat
    }
}

// Decrypt URLSessionWebSocketTask.Message
public extension URLSessionWebSocketTask.Message {
        
    /// Decrypts (i.e. performs the opposite of the Encrypt function) the ciphertext using the provided kdfNonce, ciphertext, aeadNonce, and additionalData.  All of this information is included in KeyExchangeAEADStore structs.
    ///
    ///  Then decode the decrypted data into the provided type.
    ///
    /// - Parameters:
    ///   - kes: The KeyExchangeStore used to decrypt the data.
    ///   - auth: Function that validates whether the KeyExchangeStore additionalData is valid.
    /// - Returns: The decoded JSON.
    func keyExchangeDecryptAndDecodeJSON<T: Decodable>(
        kes: KeyExchangeStore,
        auth: @escaping (String) throws -> Bool = { _ in return true }
    ) throws -> T {
        return try KeyExchangeDecryptAndDecodeJSON(
            message: self,
            kes: kes,
            auth: auth
        )
    }
}
