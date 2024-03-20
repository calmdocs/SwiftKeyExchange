//
//  Models.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 25/8/2023.
//

import Foundation
import CryptoKit

/// Struct to hold authenticated encryption with associated data (AEAD) ciphertext,
/// key derivation function (KDF) and authenticated encryption with associated data (AEAD) nonces, and additional data.
public struct KeyExchangeAEADStore: Codable, Identifiable {
    public var id: String {ciphertext}
    
    public var kdfNonce: String
    public let ciphertext: String
    public var aeadNonce: String
    public var additionalData: String

    public enum CodingKeys: String, CodingKey {
        case kdfNonce = "KDFNonce"
        case ciphertext = "Ciphertext"
        case aeadNonce = "AEADNonce"
        case additionalData = "AdditionalData"
    }
}

/// Holds an elliptic-curve cryptography (ECC) private key and public key.
public struct KeyExchangeLocalKeys {
    public var privateKey: String
    public var publicKey: String
}

/// Generic struct to hold type, id, and data Strings.
public struct KeyExchangeTypeIDAndData: Codable {
    public let type: String
    public let id:   String
    public let data: String
    
    public enum CodingKeys: String, CodingKey {
        case type = "Type"
        case id   = "ID"
        case data = "Data"
    }
    
    public init(type: String, id: String, data: String) {
        self.type = type
        self.id   = id
        self.data = data
    }
}
