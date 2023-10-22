//
//  Timestamp.swift
//  
//
//  Created by Iain McLaren on 9/9/2023.
//

import Foundation

/// Get the current time since 1970 in milliseconds.
/// - Returns: Int64 timestamp.
public func KeyExchangeCurrentTimestamp() -> Int64 {
    return Int64((Date().timeIntervalSince1970 * 1000.0).rounded())
}

/// Get the current time since 1970 in milliseconds.
/// - Returns: String timestamp.
public func KeyExchangeCurrentTimestampString() -> String {
    return String(KeyExchangeCurrentTimestamp())
}

/// Get the current time since 1970 in milliseconds.
/// - Returns: Data timestamp (utf8 encoded).
public func KeyExchangeCurrentTimestampData() -> Data {
    return Data(KeyExchangeCurrentTimestampString().utf8)
}

/// Get the base64Encoded current time since 1970 in milliseconds from an additionalData string.
/// - Parameter additionalData: base64Encoded String.
/// - Returns: Timestamp since 1970 in milliseconds.
public func KeyExchangeTimestamp(_ additionalData: String) -> Int64? {
    guard let d = Data(base64Encoded: additionalData) else {
        return nil
    }
    guard let s = String(data: d, encoding: .utf8) else {
        return nil
    }
    guard let i = Int64(s) else {
        return nil
    }
    return i
}

