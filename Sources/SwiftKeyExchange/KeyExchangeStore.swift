//
//  KeyExchangeStore.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 25/8/2023.
//

import Foundation
import SwiftUI
import CryptoKit

/// KeyExchange error.
public enum KeyExchangeError: Error {
    case invalidKey
    case invalidFormat
    case invalidCurve
    case invalidKDF
    case invalidAEAD
    case invalidAdditionalData
    
    case publicKeyNotSet
    case emptyPublicKey
    
    case invalidAdditionalDataEncoding
}

/// Elliptic-curve cryptography (ECC).
public enum KeyExchangeCurve {
    case unknown
    case curve25519
    case p256
    case p384
    case p521
}

/// Key derivation function (KDF).
public enum KeyExchangeKDF {
    case unknown
    case hkdf
}

/// Authenticated encryption with associated data (AEAD).
public enum KeyExchangeAEAD {
    case unknown
    case aesgcm
    case chachapoly
}

///  KeyExchangeStore using the Curve25519 curve, SHA256 as the hash, HKDF as the key derivation function, and AESGCM as the authenticated encryption with associated data (AEAD) cipher.
///  This is a commonly used  combination as at September 2023.
///  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string here and updated later using SetExternalPublicKey().
/// - Parameter externalPublicKey: The external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
/// - Throws: KeyExchangeStore error.
/// - Returns: KeyExchangeStore.
public func KeyExchange_Curve25519_SHA256_HKDF_AESGCM_Store(
    _ externalPublicKey: String
) throws -> KeyExchangeStore {
    return try KeyExchangeStore(
        curve: .curve25519,
        using: SHA256.self,
        kdf: .hkdf,
        aead: .aesgcm,
        externalPublicKey: externalPublicKey
    )
}

///  KeyExchangeStore using the Curve25519 curve, SHA384 as the hash, HKDF as the key derivation function, and AESGCM as the authenticated encryption with associated data (AEAD) cipher.
///  This is a commonly used  combination as at September 2023.
///  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string here and updated later using SetExternalPublicKey().
/// - Parameter externalPublicKey: The external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
/// - Throws: KeyExchangeStore error.
/// - Returns: KeyExchangeStore.
public func KeyExchange_Curve25519_SHA384_HKDF_AESGCM_Store(
    _ externalPublicKey: String
) throws -> KeyExchangeStore {
    return try KeyExchangeStore(
        curve: .curve25519,
        using: SHA384.self,
        kdf: .hkdf,
        aead: .aesgcm,
        externalPublicKey: externalPublicKey
    )
}

///  KeyExchangeStore using the Curve25519 curve, SHA512 as the hash, HKDF as the key derivation function, and AESGCM as the authenticated encryption with associated data (AEAD) cipher.
///  This is a commonly used  combination as at September 2023.
///  If we do not know the externalPublicKey when we create the Store, the externalPublicKey can be set as an empty string here and updated later using SetExternalPublicKey().
/// - Parameter externalPublicKey: The external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
/// - Throws: KeyExchangeStore error.
/// - Returns: KeyExchangeStore.
public func KeyExchange_Curve25519_SHA512_HKDF_AESGCM_Store(
    _ externalPublicKey: String
) throws -> KeyExchangeStore {
    return try KeyExchangeStore(
        curve: .curve25519,
        using: SHA512.self,
        kdf: .hkdf,
        aead: .aesgcm,
        externalPublicKey: externalPublicKey
    )
}

/// The KeyExchangeStore.
public class KeyExchangeStore: ObservableObject {
    
    private var curve: KeyExchangeCurve
    private var hashFunction: any HashFunction.Type
    private var kdf: KeyExchangeKDF
    private var aead: KeyExchangeAEAD
    private var privateKey: String
    private var localPublicKey: String
    private var externalPublicKey: String
    private var sharedSecret: SharedSecret?
    
    /// Empty KeyExchangeStore
    public init() {
        self.curve = .unknown
        self.hashFunction = SHA256.self
        self.kdf = .unknown
        self.aead = .unknown
        self.privateKey = ""
        self.localPublicKey = ""
        self.externalPublicKey = ""
    }
    
    /// Initialise the KeyExchangeStore.
    /// - Parameters:
    ///   - curve: The KeyExchangeCurve (Elliptic-curve cryptography (ECC)).
    ///   - hashFunction: any HashFunction.
    ///   - kdf: The KeyExchangeKDF (Key derivation function (KDF)).
    ///   - aead: The KeyExchangeAEAD (Authenticated encryption with associated data (AEAD)).
    ///   - externalPublicKey: The external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
    public init(
        curve: KeyExchangeCurve,
        using hashFunction: any HashFunction.Type,
        kdf: KeyExchangeKDF,
        aead: KeyExchangeAEAD,
        externalPublicKey: String
    ) throws {
        self.curve = curve
        self.hashFunction = hashFunction
        self.kdf = kdf
        self.aead = aead
        self.privateKey = ""
        self.localPublicKey = ""
        self.externalPublicKey = ""
        
        // Get privateKey and localPublicKey
        try self.resetPrivateKey("")
         
        // Set external public key
        if externalPublicKey != "" {
            try self.setExternalPublicKey(externalPublicKey)
        }
    }
    
    /// The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
    /// - Returns: The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
    public func LocalPublicKey() -> String {
        return self.localPublicKey
    }
    
    /// The external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
    /// - Returns: The external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
    public func ExternalPublicKey() throws -> String {
        if self.externalPublicKey == "" {
            throw KeyExchangeError.publicKeyNotSet
        }
        return self.externalPublicKey
    }
    
    /// The Elliptic-curve Diffie–Hellman (ECDH)  shared secret.
    /// - Returns: The  Elliptic-curve Diffie–Hellman (ECDH)  shared secret.
    public func SharedSecret() throws -> SharedSecret {
        if self.externalPublicKey == "" {
            throw KeyExchangeError.publicKeyNotSet
        }
        return self.sharedSecret!
    }
    
    /// Reset the KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key, private key, and shared secret.
    /// - Parameter privateKey: The local KeyExchangeCurve (Elliptic-curve cryptography (ECC)) private key.
    public func resetPrivateKey(_ privateKey: String) throws {
        let keyStore = try KeyExchangeCurveKeys(curve: self.curve, privateKey: privateKey)
        self.privateKey = keyStore.privateKey
        self.localPublicKey = keyStore.publicKey
        if self.externalPublicKey != "" {
            try self.setExternalPublicKey(self.externalPublicKey)
        }
    }
    
    /// Clear the external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
    public func clearExternalPublicKey() {
        self.externalPublicKey = ""
        self.sharedSecret = nil
    }
    
    /// Set the KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key, private key, and shared secret.
    /// - Parameter externalPublicKey: The external KeyExchangeCurve (Elliptic-curve cryptography (ECC)) public key.
    public func setExternalPublicKey(_ externalPublicKey: String) throws {
        self.clearExternalPublicKey()
        if externalPublicKey == "" {
            throw KeyExchangeError.emptyPublicKey
        }
        let sharedSecret = try CreateSharedSecret(
            curve: curve,
            privateKey: self.privateKey,
            publicKey: externalPublicKey
        )
        self.externalPublicKey = externalPublicKey
        self.sharedSecret = sharedSecret
    }
        
    /// Encrypt creates a random nonce (the kdfNonce), uses the key derivation function with this nonce to create a derived key, creates a second random nonce (the aeadNonce), and then encrypts the plaintext with the aeadNonce.
    ///
    /// The additionalData bytes (which do not need to be secret) are used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Parameters:
    ///   - plaintext: The plain text data to encrypt.
    ///   - additionalData: The additionalData (which does not need to be secret) is used with both the key. derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Returns: A KeyExchangeAEADStore containing both nonces, the ciphertext, and the additionalData.
    public func encrypt(
        plaintext: any DataProtocol,
        additionalData: Data
    ) throws -> KeyExchangeAEADStore {
        return try self.encryptWithNonces(
            kdfNonce: nil,
            plaintext: plaintext,
            aeadNonce: nil,
            additionalData: additionalData
        )
    }

    /// Encrypt creates a random nonce (the kdfNonce), uses the key derivation function with this nonce to create a derived key, creates a second random nonce (the aeadNonce), and then encrypts the plaintext with the aeadNonce.
    ///
    /// The additionalData bytes (which do not need to be secret) are used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    ///
    /// Encrypt with user provided nonces.  Only use specified (i.e. non-random) nonces for testing.
    /// - Parameters:
    ///   - kdfNonce: Nonce for the key derivation function (KDF).  Set to nil to create a random nonce.
    ///   - plaintext: The plain text data to encrypt.
    ///   - aeadNonce: Nonce for authenticated encryption with associated data (AEAD).  Set to nil to create a random nonce.
    ///   - additionalData: The additionalData (which does not need to be secret) is used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Returns: A KeyExchangeAEADStore containing both nonces, the ciphertext, and the additionalData.
    public func encryptWithNonces(
        kdfNonce: Data?,            // Only set manually if testing
        plaintext: any DataProtocol,
        aeadNonce: Data?,  // Only set manually if testing
        additionalData: Data
    ) throws -> KeyExchangeAEADStore {
        if self.externalPublicKey == "" {
            throw KeyExchangeError.publicKeyNotSet
        }
      
        // Create kdf and aead nonces
        let sn = kdfNonce == nil ? try AEADRandomKey(self.aead) : kdfNonce!
        let an = aeadNonce == nil ? try AEADRandomNonce(aead) : aeadNonce!
        
        // Derive symmetric key
        let symmetricKey = try KeyExchangeSymmetricKey(
            sharedSecret: self.sharedSecret!,
            using: hashFunction,
            kdf: self.kdf,
            nonce: sn,
            additionalData: additionalData
        )
            
        // Encrypt
        let ciphertext = try AEADEncrypt(
            aead: aead,
            symmetricKey: symmetricKey,
            plaintext: plaintext,
            aeadNonce: an,
            additionalData: additionalData
        )
        
        return KeyExchangeAEADStore(
            kdfNonce: sn.base64EncodedString(),
            ciphertext: ciphertext,
            aeadNonce: an.base64EncodedString(),
            additionalData: additionalData.base64EncodedString()
        )
    }
    
    /// Encode JSON struct with type, id, and data, String fields, and then encrypt the struct.
    ///
    /// Encrypt creates a random nonce (the kdfNonce), uses the key derivation function with this nonce to create a derived key, creates a second random nonce (the aeadNonce), and then encrypts the plaintext with the aeadNonce.
    ///
    /// The additionalData bytes (which do not need to be secret) are used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Parameters:
    ///   - type: type parameter.
    ///   - id: id parameter.
    ///   - data: data parameter.
    ///   - additionalData: The additionalData (which does not need to be secret) is used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Returns: A KeyExchangeAEADStore containing both nonces, the ciphertext, and the additionalData.
    public func encodeJSONAndEncrypt(
        type: String = "",
        id:   String = "",
        data: String = "",
        additionalData: Data
    ) throws -> KeyExchangeAEADStore {
        try self.encodeJSONAndEncryptWithNonces(
            type: type,
            id: id,
            data: data,
            kdfNonce: nil,
            aeadNonce: nil,
            additionalData: additionalData
        )
    }
    
    /// Encode JSON struct with type, id, and data, String fields, and encrypt the struct with user provided nonces.
    /// Only use specified (i.e. non-random) nonces for testing.
    ///
    /// Encrypt creates a random nonce (the kdfNonce), uses the key derivation function with this nonce to create a derived key, creates a second random nonce (the aeadNonce), and then encrypts the plaintext with the aeadNonce.
    ///
    /// The additionalData bytes (which do not need to be secret) are used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Parameters:
    ///   - type: type parameter.
    ///   - id: id parameter.
    ///   - data: data parameter.
    ///   - kdfNonce: Nonce for the key derivation function (KDF).  Set to nil to create a random nonce.
    ///   - aeadNonce: Nonce for authenticated encryption with associated data (AEAD).  Set to nil to create a random nonce.
    ///   - additionalData: The additionalData (which does not need to be secret) is used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Returns: A KeyExchangeAEADStore containing both nonces, the ciphertext, and the additionalData.
    public func encodeJSONAndEncryptWithNonces(
        type: String = "",
        id:   String = "",
        data: String = "",
        kdfNonce: Data?,       // Only set manually if testing
        aeadNonce: Data?,             // Only set manually if testing
        additionalData: Data
    ) throws -> KeyExchangeAEADStore {
        if self.externalPublicKey == "" {
            throw KeyExchangeError.publicKeyNotSet
        }
        
        let value = KeyExchangeTypeIDAndData(
            type: type,
            id: id,
            data: data
        )
        let plaintext = try JSONEncoder().encode(value)
        
        return try self.encryptWithNonces(
            kdfNonce: kdfNonce,
            plaintext: plaintext,
            aeadNonce: aeadNonce,
            additionalData: additionalData
        )
    }
    
    /// Encode generic encodable value to JSON, and encrypt.
    ///
    /// Encrypt creates a random nonce (the kdfNonce), uses the key derivation function with this nonce to create a derived key, creates a second random nonce (the aeadNonce), and then encrypts the plaintext with the aeadNonce.
    ///
    /// The additionalData bytes (which do not need to be secret) are used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Parameters:
    ///   - value: The Encodable value to encrypt.
    ///   - additionalData: The additionalData (which does not need to be secret) is used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Returns: A KeyExchangeAEADStore containing both nonces, the ciphertext, and the additionalData.
    public func encodeJSONAndEncrypt<T>(
        _ value: T,
        additionalData: Data
    ) throws -> KeyExchangeAEADStore where T : Encodable {
        try self.encodeJSONAndEncryptWithNonces(
            value,
            kdfNonce: nil,
            aeadNonce: nil,
            additionalData: additionalData
        )
    }
    
    /// Encode generic encodable value to JSON, and encrypt with user provided nonces.
    /// Only use specified (i.e. non-random) nonces for testing.
    ///
    /// Encrypt creates a random nonce (the kdfNonce), uses the key derivation function with this nonce to create a derived key, creates a second random nonce (the aeadNonce), and then encrypts the plaintext with the aeadNonce.
    ///
    /// The additionalData bytes (which do not need to be secret) are used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Parameters:
    ///   - value: The Encodable value to encrypt.
    ///   - kdfNonce: Nonce for the key derivation function (KDF).  Set to nil to create a random nonce.
    ///   - aeadNonce: Nonce for authenticated encryption with associated data (AEAD).  Set to nil to create a random nonce.
    ///   - additionalData: The additionalData (which does not need to be secret) is used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Returns: A KeyExchangeAEADStore containing both nonces, the ciphertext, and the additionalData.
    public func encodeJSONAndEncryptWithNonces<T>(
        _ value: T,
        kdfNonce: Data?,           // Only set manually if testing
        aeadNonce: Data?,          // Only set manually if testing
        additionalData: Data
    ) throws -> KeyExchangeAEADStore where T : Encodable {
        if self.externalPublicKey == "" {
            throw KeyExchangeError.publicKeyNotSet
        }
        
        let plaintext = try JSONEncoder().encode(value)
        
        return try self.encryptWithNonces(
            kdfNonce: kdfNonce,
            plaintext: plaintext,
            aeadNonce: aeadNonce,
            additionalData: additionalData
        )
    }
    
    /// Decrypt decrypts (i.e. performs the opposite of the Encrypt function) the ciphertext using the provided kdfNonce, ciphertext, aeadNonce, and additionalData.  All of this information is included in KeyExchangeAEADStore structs.
    /// - Parameters:
    ///   - kdfNonce: Nonce for the key derivation function (KDF).
    ///   - ciphertext: The encrypted text.
    ///   - aeadNonce: Nonce for authenticated encryption with associated data (AEAD).
    ///   - additionalData: The additionalData (which does not need to be secret) is used with both the key derivation function and when encrypting (using encryption with associated data (AEAD) encryption).
    /// - Returns: The decrypted Data.
    public func decrypt(
        kdfNonce: String,
        ciphertext: String,
        aeadNonce: String,
        additionalData: String
    ) throws -> Data {
        if self.externalPublicKey == "" {
            throw KeyExchangeError.publicKeyNotSet
        }
        
        // Derive symmetric key
        let symmetricKey = try KeyExchangeSymmetricKey(
            sharedSecret: self.sharedSecret!,
            using: hashFunction,
            kdf: self.kdf,
            nonce: Data(base64Encoded: kdfNonce)!,
            additionalData: Data(base64Encoded: additionalData)!
        )
        
        // Decrypt
        return try AEADDecrypt(
            aead: self.aead,
            symmetricKey: symmetricKey,
            ciphertext: ciphertext,
            aeadNonce: aeadNonce,
            additionalData: additionalData
        )
    }
    
    /// Decrypt decrypts (i.e. performs the opposite of the Encrypt function) the ciphertext using the provided kdfNonce, ciphertext, aeadNonce, and additionalData included in the provided KeyExchangeAEADStore struct.
    /// - Parameter v: The KeyExchangeAEADStore.
    /// - Returns: The decrypted Data.
    public func decryptAEADStore(_ v: KeyExchangeAEADStore) throws -> Data {
        return try self.decrypt(
            kdfNonce: v.kdfNonce,
            ciphertext: v.ciphertext,
            aeadNonce: v.aeadNonce,
            additionalData: v.additionalData
        )
    }
}


