//
//  PEM.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 23/8/2023.
//

import Foundation
import CryptoKit

/// The Privacy-Enhanced Mail (PEM) error.
public enum PEMError: Error {
    case doesNotExist
}

/// Extracts the private key from a String in the Privacy-Enhanced Mail (PEM) format.
/// - Parameter s: Source string.
/// - Throws: PEMError.doesNotExist.
/// - Returns: The private key string.
public func PEMFromString(_ s: String) throws -> String {
    if !s.contains("-----BEGIN PUBLIC KEY-----") {
        throw PEMError.doesNotExist
    }
    let pem = s
        .components(
            separatedBy: "-----BEGIN PUBLIC KEY-----\n")[1]
        .components(
            separatedBy: "\n-----END PUBLIC KEY-----")[0]
    if pem == "" {
        throw PEMError.doesNotExist
    }
    return pem
}

/// Search for a private key String in Privacy-Enhanced Mail (PEM) format.
/// - Parameter output: The string to search for a external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
/// - Returns: The public key String or nil if no key is found
public func PEMSearchString(_ output: String) -> String? {
    guard let publicKey = try? PEMFromString(output) else {
        return nil
    }
    return publicKey
}
