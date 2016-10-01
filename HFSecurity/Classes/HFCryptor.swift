//
//  HFCryptor.swift
//  Pods
//
//  Created by DragonCherry on 6/30/16.
//
//

import Foundation
import RNCryptor

public class HFCryptor {
    
    private static let kUUIDSize = 36
    
    /// encrypts plain data and returns encrypted data
    /// - parameter data: UTF-8 encoded plain data to encrypt
    /// - parameter key: AES256 key(length 32)
    /// - returns: NSData encrypted data
    public static func encrypt(data: NSData, key: String) -> NSData? {
        
        guard key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding) != kCCKeySizeAES256 else {
            logw("\(#function) - invalid key(\(key)) with length: \(key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))")
            return nil
        }
        
        return RNCryptor.encryptData(data, password: key)
    }
    
    
    /// decrypts encrypted data and returns plain data
    /// - parameter cipherData: encrypted data returned by ACCryptor.encrypt(data:key:)
    /// - parameter key: AES256 key(length 32)
    /// - returns: NSData decrypted data
    public static func decrypt(cipherData: NSData, key: String) -> NSData? {
        
        guard key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding) != kCCKeySizeAES256 else {
            logw("\(#function) - invalid key(\(key)) with length: \(key.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))")
            return nil
        }
        
        do {
            return try RNCryptor.decryptData(cipherData, password: key)
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
    public static func encrypt(plainText: String, key: String, augment: Bool? = false) -> String? {
        
        guard let bodyData = plainText.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) else {
            return nil
        }
        
        var cipherData: NSData? = nil
        
        if boolean(augment) {
            if let data = appendSuffix(bodyData) {
                cipherData = HFCryptor.encrypt(data, key: key)
            }
        } else  {
            cipherData = HFCryptor.encrypt(bodyData, key: key)
        }
        
        if let cipherData = cipherData {
            return cipherData.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0))
        } else {
            return nil
        }
    }
    
    /// decrypts encrypted Base64 text and returns plain text: Base64(E(UTF8(P))) -> P
    /// - parameter cipherText: cipher text returned by ACCryptor.encrypt(cipherText:key:augment:)
    /// - parameter key: AES256 key(length 32)
    /// - parameter augment: set true to remove additional UUID text after get plain text
    /// - returns: NSData decrypted data
    public static func decrypt(cipherText: String, key: String, augment: Bool? = false) -> String? {
        
        guard let cipherData = NSData(base64EncodedString: cipherText, options: NSDataBase64DecodingOptions(rawValue: 0)) else {
            return nil
        }
        
        guard let decryptedData = decrypt(cipherData, key: key) else {
            return nil
        }
        
        var decryptedText: String? = nil
        
        if boolean(augment) {
            if let deaugmented = removeSuffix(decryptedData) {
                decryptedText = String(data: deaugmented, encoding: NSUTF8StringEncoding)
            }
        } else {
            decryptedText = String(data: decryptedData, encoding: NSUTF8StringEncoding)
        }
        return decryptedText
    }
    
    /// append UUID text at the end of data
    /// - parameter data: original source
    /// - returns: NSData concatenated data
    private static func appendSuffix(data: NSData) -> NSData? {
        
        let mutableData = NSMutableData(data: data)
        guard let suffixData: NSData = NSUUID().UUIDString.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false) else {
            logw("failed to get UUID data")
            return nil
        }
        mutableData.appendData(suffixData)
        return mutableData as NSData
    }
    
    /// remove UUID text at the end of data
    /// - parameter data: concatenated data that returned by appendSuffix(data:)
    /// - returns: NSData original data
    private static func removeSuffix(data: NSData) -> NSData? {
        
        let expectedLength = data.length - kUUIDSize
        guard expectedLength >= 0 else {
            return nil
        }
        let range: NSRange = NSMakeRange(0, expectedLength)
        return data.subdataWithRange(range)
    }
}