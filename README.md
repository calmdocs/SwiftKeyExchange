# SwiftKeyExchange
Swift Diffie–Hellman key exchange ([DHKE](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange)) library built using the [Apple CryptoKit Framework](https://developer.apple.com/documentation/cryptokit/).

Designed to mirror the golang [calmdocs/keyexchange](https://github.com/calmdocs/keyexchange) library.  For example we use the same test keys, nonces, and results in this library as we use in the golang [calmdocs/keyexchange](https://github.com/calmdocs/keyexchange) library.

## A note on security

We have been as conservative as possible when creating this library.  See the security discussion below.  However, please note that you use this library, and the code in this repo, at your own risk, and we accept no liability in relation to its use.

## Example
```
let curve = KeyExchangeCurve.curve25519
let hashFunction = SHA256.self
let kdf = KeyExchangeKDF.hkdf
let aead = KeyExchangeAEAD.aesgcm

let plaintext = "exampleplaintext".data(using: .utf8)!
let additionalData = Data("abc".utf8)

// alice store
let aliceStore = try KeyExchangeStore(
    curve: curve,
    using: hashFunction,
    kdf: kdf,
    aead: aead,
    externalPublicKey: ""
)

// bob store
let bobStore = try KeyExchangeStore(
    curve: curve,
    using: hashFunction,
    kdf: kdf,
    aead: aead,
    externalPublicKey: "",
)

// Add privacte keys to the stores.
try! aliceStore.setExternalPublicKey(bobStore.LocalPublicKey())
try! bobStore.setExternalPublicKey(aliceStore.LocalPublicKey())

// Alice encrypt.
var v = try! aliceStore.encrypt(
    plaintext: plaintext,
    additionalData: additionalData
)

// Bob decrypt.
let bobPlaintext = try bobStore.decrypt(
    kdfNonce: v.kdfNonce,
    ciphertext: v.ciphertext,
    aeadNonce: v.aeadNonce,
    additionalData: v.additionalData
)

// Bob encrypt.
v = try! bobStore.encrypt(
    plaintext: plaintext,
    additionalData: additionalData
)

// Alice decrypt.
let alicePlaintext = try aliceStore.decrypt(
    kdfNonce: v.kdfNonce,
    ciphertext: v.ciphertext,
    aeadNonce: v.aeadNonce,
    additionalData: v.additionalData
)

print(plaintext == alicePlaintext)
print(plaintext == bobPlaintext)
```

## Security approach

As mentioned above, we have been as conservative as possible when creating this library.  For example, we have only used Apple's Cryptokit library, and have not used any third party cryptography libraries to create this package.  We will try to follow SemVer, but may not if there are security issues and/or as the underlying encryption used by this library becomes insecure over time. 

Please notify us of any security issues by creating a github issue. Please propose how you would like to securely communicate with us (via email or other communication method). Please do not post the security issue on github.  

## Why not just use HPKE?

Because, when this library was written:
- [HPKE](https://developer.apple.com/documentation/cryptokit/hpke) was in beta in Apple's Cryptokit library;
- there is no HPKE implementation in golang's standard library, or even in golang.org/x/crypto; and
- using [HPKE](https://developer.apple.com/documentation/cryptokit/hpke) would not allow any messages to be missed or dropped, and one of the author's use-case for this library actually *requires* some messages to be missed or dropped (for example, this is useful for [calmdocs/SwiftStreamManager](https://github.com/calmdocs/SwiftStreamManager)).

We will probably add [HPKE](https://developer.apple.com/documentation/cryptokit/hpke) to this library, as well as to its golang counterpart ([calmdocs/keyexchange](https://github.com/calmdocs/keyexchange)) at some point.




