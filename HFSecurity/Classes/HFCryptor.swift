//
//  HFCryptor.swift
//  Pods
//
//  Created by DragonCherry on 6/30/16.
//
//

import RNCryptor
import TinyLog
import OptionalTypes

open class HFCryptor {
    
    fileprivate static let kUUIDSize = 36
    
    /// encrypts plain data and returns encrypted data
    /// - parameter data: UTF-8 encoded plain data to encrypt
    /// - parameter key: AES256 key(length 32)
    /// - returns: NSData encrypted data
    open static func encrypt(_ data: Data, key: String) -> Data? {
        
        guard key.lengthOfBytes(using: String.Encoding.utf8) != kCCKeySizeAES256 else {
            logw("\(#function) - invalid key(\(key)) with length: \(key.lengthOfBytes(using: String.Encoding.utf8))")
            return nil
        }
        
        return RNCryptor.encrypt(data: data, withPassword: key)
    }
    
    
    /// decrypts encrypted data and returns plain data
    /// - parameter cipherData: encrypted data returned by ACCryptor.encrypt(data:key:)
    /// - parameter key: AES256 key(length 32)
    /// - returns: NSData decrypted data
    open static func decrypt(_ cipherData: Data, key: String) -> Data? {
        
        guard key.lengthOfBytes(using: String.Encoding.utf8) != kCCKeySizeAES256 else {
            logw("\(#function) - invalid key(\(key)) with length: \(key.lengthOfBytes(using: String.Encoding.utf8))")
            return nil
        }
        
        do {
            return try RNCryptor.decrypt(data: cipherData, withPassword: key)
        } catch {
            loge(error)
            return nil
        }
    }
    
    /// decrypts encrypted Base64 text and returns plain data: P -> Base64(E(UTF8(P)))
    /// - parameter plainText: plain text to encrypt
    /// - parameter key: AES256 key(length 32)
    /// - parameter augment: optional boolean for appending additional text to retrieve random cipher text on every encryption
    /// - returns: NSData decrypted data
    open static func encrypt(_ plainText: String, key: String, isAugmented: Bool = false) -> String? {
        
        guard let bodyData = plainText.data(using: String.Encoding.utf8, allowLossyConversion: false) else {
            return nil
        }
        
        var cipherData: Data? = nil
        
        if isAugmented {
            if let data = appendSuffix(bodyData) {
                cipherData = HFCryptor.encrypt(data, key: key)
            }
        } else  {
            cipherData = HFCryptor.encrypt(bodyData, key: key)
        }
        
        if let cipherData = cipherData {
            return cipherData.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0))
        } else {
            return nil
        }
    }
    
    /// decrypts encrypted Base64 text and returns plain text: Base64(E(UTF8(P))) -> P
    /// - parameter cipherText: cipher text returned by ACCryptor.encrypt(cipherText:key:augment:)
    /// - parameter key: AES256 key(length 32)
    /// - parameter augment: set true to remove additional UUID text after get plain text
    /// - returns: NSData decrypted data
    open static func decrypt(_ cipherText: String, key: String, isAugmented: Bool = false) -> String? {
        
        guard let cipherData = Data(base64Encoded: cipherText, options: NSData.Base64DecodingOptions(rawValue: 0)) else {
            return nil
        }
        
        guard let decryptedData = decrypt(cipherData, key: key) else {
            return nil
        }
        
        var decryptedText: String? = nil
        
        if isAugmented {
            if let deaugmented = removeSuffix(decryptedData) {
                decryptedText = String(data: deaugmented, encoding: String.Encoding.utf8)
            }
        } else {
            decryptedText = String(data: decryptedData, encoding: String.Encoding.utf8)
        }
        return decryptedText
    }
    
    /// append UUID text at the end of data
    /// - parameter data: original source
    /// - returns: NSData concatenated data
    fileprivate static func appendSuffix(_ data: Data) -> Data? {
        var mutableData = data
        guard let suffixData: Data = UUID().uuidString.data(using: String.Encoding.utf8, allowLossyConversion: false) else {
            logw("failed to get UUID data")
            return nil
        }
        mutableData.append(suffixData)
        return mutableData as Data
    }
    
    /// remove UUID text at the end of data
    /// - parameter data: concatenated data that returned by appendSuffix(data:)
    /// - returns: NSData original data
    fileprivate static func removeSuffix(_ data: Data) -> Data? {
        let expectedLength = data.count - kUUIDSize
        guard expectedLength >= 0 else {
            return nil
        }
        return data.subdata(in: 0..<expectedLength)
    }
}
