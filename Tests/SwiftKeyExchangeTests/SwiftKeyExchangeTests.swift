import XCTest
import CryptoKit
@testable import SwiftKeyExchange

final class SwiftKeyExchangeTests: XCTestCase {
    
    func testKeyExchange() throws {
        let curve = KeyExchangeCurve.curve25519
        let hashFunction = SHA256.self
        let kdf = KeyExchangeKDF.hkdf
        let aead = KeyExchangeAEAD.aesgcm
        
        let alicePrivateKey = "DDooYaf2wbGQ2V1MWj8jM+KxLxu6apnMYetwdHMY4vI="
        let alicePublicKey = "xql2dqP8MqbQSHgwMdTQSaSqUUtaPewDKzT/FR9xpG8="
        let bobPrivateKey = "gBeL2f79WIcTfW45zvMj7SZcJBOAE/sbUAb5ch7WA0Y="
        let bobPublicKey = "dXuLU5sg+svTjqnk6UvWidfJS4DeDBbs037A4fPhAiU="
        
        let kdfNonce = Data("4780bf3061ebbaab7562d3ef".utf8)
        let plaintext = "exampleplaintext".data(using: .utf8)!
        let aeadNonceText = "hAqd8PI6RlEhVikF"
        let aeadNonce = Data(base64Encoded: aeadNonceText)!
        let additionalData = Data("abc".utf8)
        
        let ciphertext = "hAqd8PI6RlEhVikFlLWMvnibSUxvhIKue/0opwrnrJduO/8Lt/xF52C+wIk="
        
        // alice store
        let aliceStore = try KeyExchangeStore(
            curve: curve,
            using: hashFunction,
            kdf: kdf,
            aead: aead,
            externalPublicKey: bobPublicKey
        )
        try aliceStore.resetPrivateKey(alicePrivateKey)
        
        // bob store
        let bobStore = try KeyExchangeStore(
            curve: curve,
            using: hashFunction,
            kdf: kdf,
            aead: aead,
            externalPublicKey: alicePublicKey
        )
        try bobStore.resetPrivateKey(bobPrivateKey)
        
        // Alice encrypt
        var v = try aliceStore.encryptWithNonces(
            kdfNonce: kdfNonce,
            plaintext: plaintext,
            aeadNonce: aeadNonce,
            additionalData: additionalData
        )
        XCTAssertEqual(
            kdfNonce.base64EncodedString(),
            v.kdfNonce
        )
        XCTAssertEqual(ciphertext, v.ciphertext)
        XCTAssertEqual(
            aeadNonce.base64EncodedString(),
            v.aeadNonce
        )
        XCTAssertEqual(
            additionalData.base64EncodedString(),
            v.additionalData
        )
       
        // Bob decrypt
        let bobPlaintext = try bobStore.decrypt(
            kdfNonce: v.kdfNonce,
            ciphertext: v.ciphertext,
            aeadNonce: v.aeadNonce,
            additionalData: v.additionalData
        )
        XCTAssertEqual(plaintext, bobPlaintext)
        
        // Bob encrypt
        v = try bobStore.encryptWithNonces(
            kdfNonce: kdfNonce,
            plaintext: plaintext,
            aeadNonce: aeadNonce,
            additionalData: additionalData
        )
        XCTAssertEqual(
            kdfNonce.base64EncodedString(),
            v.kdfNonce
        )
        XCTAssertEqual(ciphertext, v.ciphertext)
        XCTAssertEqual(
            aeadNonce.base64EncodedString(),
            v.aeadNonce
        )
        XCTAssertEqual(
            additionalData.base64EncodedString(),
            v.additionalData
        )
       
        // Alice decrypt
        let alicePlaintext = try aliceStore.decrypt(
            kdfNonce: v.kdfNonce,
            ciphertext: v.ciphertext,
            aeadNonce: v.aeadNonce,
            additionalData: v.additionalData
        )
        XCTAssertEqual(plaintext, alicePlaintext)
    }
    
    func testPEM() throws {
        
        // Success
        var s = "-----BEGIN PUBLIC KEY-----\n"
            .appending("abc")
            .appending("\n-----END PUBLIC KEY-----")
        XCTAssertEqual(try PEMFromString(s), "abc")
        
        // Empty
        s = ""
        XCTAssertThrowsError(try PEMFromString(s)) { error in
            XCTAssertEqual(error as! PEMError, PEMError.doesNotExist)
        }

        // Invalid
        s = "dwegerfgertg"
        XCTAssertThrowsError(try PEMFromString(s)) { error in
            XCTAssertEqual(error as! PEMError, PEMError.doesNotExist)
        }
        
        // Valid but empty
        s = "-----BEGIN PUBLIC KEY-----\n"
            .appending("")
            .appending("\n-----END PUBLIC KEY-----")
        XCTAssertThrowsError(try PEMFromString(s)) { error in
            XCTAssertEqual(error as! PEMError, PEMError.doesNotExist)
        }
    }
    
    func testCurve25519() throws {
        let alicePrivateKey = "DDooYaf2wbGQ2V1MWj8jM+KxLxu6apnMYetwdHMY4vI="
        let alicePublicKey = "xql2dqP8MqbQSHgwMdTQSaSqUUtaPewDKzT/FR9xpG8="
        let bobPrivateKey = "gBeL2f79WIcTfW45zvMj7SZcJBOAE/sbUAb5ch7WA0Y="
        let bobPublicKey = "dXuLU5sg+svTjqnk6UvWidfJS4DeDBbs037A4fPhAiU="
        let expectedSecretString = "3Nji+LTOtQpaVBuzPN2XgBPUlAn961hGYlSMweTjERI="
        
        // Alice
        let alicePrivateStore = try Curve25519PrivateStore(alicePrivateKey)
        let aliceAuthToken = alicePrivateStore.publicKey.rawRepresentation.base64EncodedString()
        XCTAssertEqual(aliceAuthToken, alicePublicKey)
        let alicePublicStore = try Curve25519PublicStore(alicePublicKey) // To send to bob
        
        // Bob
        let bobPrivateStore = try Curve25519PrivateStore(bobPrivateKey)
        let bobAuthToken = bobPrivateStore.publicKey.rawRepresentation.base64EncodedString()
        XCTAssertEqual(bobAuthToken, bobPublicKey)
        let bobPublicStore = try Curve25519PublicStore(bobPublicKey) // To send to alice
  
        // Alice shared secret
        let aliceSharedSecret = try alicePrivateStore.sharedSecretFromKeyAgreementData(
            bobPublicStore).base64EncodedString()
        XCTAssertEqual(aliceSharedSecret, expectedSecretString)
        
        // Bob shared secret
        let bobSharedSecret = try bobPrivateStore.sharedSecretFromKeyAgreementData(
            alicePublicStore).base64EncodedString()
        XCTAssertEqual(bobSharedSecret, expectedSecretString)

        // Alice's and bob's shared secrets are equal
        XCTAssertEqual(aliceSharedSecret, bobSharedSecret)
    }
    
    func testHKDF() throws {
        let curve = KeyExchangeCurve.curve25519
        let hashFunction = SHA256.self
        let kdf = KeyExchangeKDF.hkdf
        let aead = KeyExchangeAEAD.aesgcm
        
        let nonce = Data("4780bf3061ebbaab7562d3ef".utf8)
        let additionalData = Data("abc".utf8)
        
        let alicePrivateKey = "DDooYaf2wbGQ2V1MWj8jM+KxLxu6apnMYetwdHMY4vI="
        let alicePublicKey = "xql2dqP8MqbQSHgwMdTQSaSqUUtaPewDKzT/FR9xpG8="
        let bobPrivateKey = "gBeL2f79WIcTfW45zvMj7SZcJBOAE/sbUAb5ch7WA0Y="
        let bobPublicKey = "dXuLU5sg+svTjqnk6UvWidfJS4DeDBbs037A4fPhAiU="
        
        let expectedHKDF = "LhxSAkC2BKy6FsGy+hJ/U+mJwzxXl5tvCYzEo0Q1bkE="
        
        // alice store
        let aliceStore = try KeyExchangeStore(
            curve: curve,
            using: hashFunction,
            kdf: kdf,
            aead: aead,
            externalPublicKey: bobPublicKey
        )
        try aliceStore.resetPrivateKey(alicePrivateKey)
        
        // bob store
        let bobStore = try KeyExchangeStore(
            curve: curve,
            using: hashFunction,
            kdf: kdf,
            aead: aead,
            externalPublicKey: alicePublicKey
        )
        try bobStore.resetPrivateKey(bobPrivateKey)
        
        let aliceHKDF = try KeyExchangeSymmetricKey(
            sharedSecret: try aliceStore.SharedSecret(),
            using: hashFunction,
            kdf: kdf,
            nonce: nonce,
            additionalData: additionalData
        ).data()
        
        let bobHKDF = try KeyExchangeSymmetricKey(
            sharedSecret: try bobStore.SharedSecret(),
            using: hashFunction,
            kdf: kdf,
            nonce: nonce,
            additionalData: additionalData
        ).data()
        
        // Alice's and bob's shared secrets are equal
        XCTAssertEqual(aliceHKDF, bobHKDF)
        XCTAssertEqual(aliceHKDF.base64EncodedString(), expectedHKDF)
    }
    
    func testAESCGM() throws {
        let key = "LhxSAkC2BKy6FsGy+hJ/U+mJwzxXl5tvCYzEo0Q1bkE="
        let plaintext = "exampleplaintext"
        let nonceText = "hAqd8PI6RlEhVikF"
        let additionalDataString = "abc"
        
        // nonce + cyphertext + additionalData
        let ciphertextString = "hAqd8PI6RlEhVikFlLWMvnibSUxvhIKue/0opwrnrJduO/8Lt/xF52C+wIk="
        
        let symmetricKey = SymmetricKey(data: Data(base64Encoded: key)!)
        let nonce = try AES.GCM.Nonce(data: Data(base64Encoded: nonceText)!)
        let additionalData = additionalDataString.data(using: .utf8)!
        let ciphertext = Data(base64Encoded: ciphertextString)

        // Encrypt
        let sealedBox = try AESGCMEncrypt(
            symmetricKey: symmetricKey,
            message: plaintext.data(using: .utf8)!,
            nonce: nonce,
            additionalData: additionalData
        )
        XCTAssertEqual(
            ciphertext?.base64EncodedString(),
            sealedBox.combined!.base64EncodedString()
        )
         
        // Decrypt
        let decryptedData = try AESGCMDecrypt(
            symmetricKey: symmetricKey,
            combined: sealedBox.combined!,
            additionalData: additionalData
        )
        let decryptedMessageString = String(data: decryptedData, encoding: .utf8)!
        XCTAssertEqual(
            decryptedMessageString,
            plaintext
        )
    }
    
    func testChaChaPoly() throws {
        let key = "LhxSAkC2BKy6FsGy+hJ/U+mJwzxXl5tvCYzEo0Q1bkE="
        let plaintext = "exampleplaintext"
        let nonceText = "hAqd8PI6RlEhVikF"
        let additionalDataString = "abc"
        
        // nonce + cyphertext + additionalData
        let ciphertextString = "hAqd8PI6RlEhVikFovtSMzKvyGqggJvjtsK3ZFnyvIhU+YL/+taFktRMSlI="
        
        let symmetricKey = SymmetricKey(data: Data(base64Encoded: key)!)
        let nonce = try ChaChaPoly.Nonce(data: Data(base64Encoded: nonceText)!)
        let additionalData = additionalDataString.data(using: .utf8)!
        let ciphertext = Data(base64Encoded: ciphertextString)

        // Encrypt
        let sealedBox = try ChaChaPolyEncrypt(
            symmetricKey: symmetricKey,
            message: plaintext.data(using: .utf8)!,
            nonce: nonce,
            additionalData: additionalData
        )
        XCTAssertEqual(
            ciphertext?.base64EncodedString(),
            sealedBox.combined.base64EncodedString()
        )
         
        // Decrypt
        let decryptedData = try ChaChaPolyDecrypt(
            symmetricKey: symmetricKey,
            combined: sealedBox.combined,
            additionalData: additionalData
        )
        let decryptedMessageString = String(data: decryptedData, encoding: .utf8)!
        XCTAssertEqual(
            decryptedMessageString,
            plaintext
        )
    }
}
