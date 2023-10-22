//
//  RandomData.swift
//  SwiftKeyExchange
//
//  Created by Iain McLaren on 23/8/2023.
//

import Foundation
import CryptoKit

/// Create random Data.
/// - Parameter byteCount: The number of bytes required.
/// - Returns: The random Data.
public func KeyExchangeRandomBytes(_ byteCount: Int) -> Data {
    let symmetricKeySize = SymmetricKeySize(bitCount: byteCount*8)
    let sk = SymmetricKey(size: symmetricKeySize)
    return sk.withUnsafeBytes { Data($0) }
}

/// Create random Data.
/// - Parameter byteCount: The number of bits required.
/// - Returns: The random Data.
public func KeyExchangeRandomBits(_ bitCount: Int) -> Data {
    let symmetricKeySize = SymmetricKeySize(bitCount: bitCount)
    let sk = SymmetricKey(size: symmetricKeySize)
    return sk.withUnsafeBytes { Data($0) }
}
