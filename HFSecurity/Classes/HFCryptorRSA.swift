//
//  HFCryptorRSA.swift
//  Pods
//
//  Created by DragonCherry on 6/30/16.
//
//

import HFUtility
import CoreFoundation
import Security
import RNCryptor

public class HFCryptorRSA {
    
    private let kTemporaryKeyTag: String = "kTemporaryKeyTag"
    
    private enum HFCryptorRSAProcessType {
        case encrypt
        case decrypt
    }
    
    public enum HFCryptorRSAKeySize: Int {
        case bits512    = 512
        case bits1024   = 1024
        case bits2048   = 2048
        case bits4096   = 4096
    }
    
    var keySize: HFCryptorRSAKeySize = .bits2048
    
    // MARK: - Private Key
    private var privateTag: String!
    private var privateSecKey: SecKey? = nil
    public var privateKey: NSData? {
        return keyDataForTag(self.privateTag)
    }
    
    // MARK: - Public Key
    private var publicTag: String!
    private var publicSecKey: SecKey? = nil
    public var publicKey: NSData? {
        return keyDataForTag(self.publicTag)
    }
    
    // MARK: - Initializer
    public init(privateTag: String, publicTag: String) {
        self.privateTag = privateTag
        self.privateSecKey = self.secKeyForTag(self.privateTag)
        
        self.publicTag = publicTag
        self.publicSecKey = self.secKeyForTag(self.publicTag)
    }
    
    // MARK: - API
    public func generateKeyPair(size: HFCryptorRSAKeySize = .bits2048, writeOnKeychain: Bool = false, regenerate: Bool = false) -> Bool {
        
        self.keySize = size
        
        // clear if regeneration flag is on
        if regenerate {
            self.updateKey(self.privateTag, keyData: nil)
            self.updateKey(self.publicTag, keyData: nil)
        }
        
        // set option for private key
        let privateAttributes = [
            String(kSecAttrIsPermanent): writeOnKeychain,
            String(kSecAttrCanEncrypt): false,
            String(kSecAttrCanDecrypt): true,
            String(kSecAttrCanSign): true,
            String(kSecAttrCanVerify): false,
            String(kSecAttrApplicationTag): self.privateTag
        ]
        
        // set option for public key
        let publicAttributes = [
            String(kSecAttrIsPermanent): writeOnKeychain,
            String(kSecAttrCanEncrypt): true,
            String(kSecAttrCanDecrypt): false,
            String(kSecAttrCanSign): false,
            String(kSecAttrCanVerify): true,
            String(kSecAttrApplicationTag): self.publicTag
        ]
        
        // set option for key pair
        let pairAttributes = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits): size.rawValue,
            String(kSecPublicKeyAttrs): publicAttributes,
            String(kSecPrivateKeyAttrs): privateAttributes
        ]
        
        // generate key pair
        let status = SecKeyGeneratePair(pairAttributes, &self.publicSecKey, &self.privateSecKey)
        if errSecSuccess == status {
            log("Successfully generated key pair on \(writeOnKeychain ? "keychain" : "memory") with size of \(size.rawValue) bit.")
            log("[Private Key] \(self.keyDataForTag(self.privateTag)?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0)))")
            log("[Public Key] \(self.keyDataForTag(self.publicTag)?.base64EncodedStringWithOptions(NSDataBase64EncodingOptions(rawValue: 0)))")
            return true
        } else {
            loge("Failed to generate RSA key pair with code: \(status)")
            return false
        }
    }
    
    /// encrypt
    public func encrypt(data: NSData, key: NSData? = nil, padding: SecPadding = .None) -> NSData? {
        return process(data, type: .encrypt, key: key, padding: padding)
    }
    
    public func decrypt(data: NSData, key: NSData? = nil, padding: SecPadding = .None) -> NSData? {
        return process(data, type: .decrypt, key: key, padding: padding)
    }
    
    /// encrypt or decrypt data with given key
    private func process(data: NSData, type: HFCryptorRSAProcessType, key: NSData? = nil, padding: SecPadding = .None) -> NSData? {
        
        var processingSecKey: SecKey? = nil
        
        // log data size
        log("Data size to process: \(data.length), key size: \(self.keySize.rawValue)")
        
        if type == .encrypt {
            guard data.length < (self.keySize.rawValue / 8) else {
                loge("Data size exceeds its limit.")
                return nil
            }
        }
        
        // save public key data on temporary space in keychain and retrieve it as SecKey type if it has designated key
        if let designatedKey = key {
            
            if self.updateKey(kTemporaryKeyTag, keyData: designatedKey) {
                
                // check key first
                guard let designatedSecKey = self.secKeyForTag(kTemporaryKeyTag) else {
                    return nil
                }
                processingSecKey = designatedSecKey
                log("Retrieved SecKey using designated key data.")
            } else {
                loge("Failed to make SecKey using external key data.")
                return nil
            }
        } else {
            
            // retrieve key by given tag passed by init
            var existingKey: SecKey? = nil
            if type == .encrypt {
                existingKey = self.publicSecKey
            } else {
                existingKey = self.privateSecKey
            }
            
            if let existingKey = existingKey {
                log("Retrieved SecKey using existing key.")
                processingSecKey = existingKey
            } else {
                loge("Cannot retrieve any valid key for \(type == .encrypt ? "encryption" : "decryption").")
                return nil
            }
        }
        
        // process data using SecKey
        if let processingSecKey = processingSecKey {
            let plainBytes = UnsafePointer<UInt8>(data.bytes)
            let plainBytesLength = data.length
            
            var cipherBytesLength = SecKeyGetBlockSize(processingSecKey)
            
            guard let cipherData = NSMutableData(length: cipherBytesLength) else {
                log("Failed to allocate NSMutableData with length \(cipherBytesLength)")
                return nil
            }
            let cipherBytes = UnsafeMutablePointer<UInt8>(cipherData.mutableBytes)
            
            var status = errSecSuccess
            if type == .encrypt {
                status = SecKeyEncrypt(processingSecKey, padding, plainBytes, plainBytesLength, cipherBytes, &cipherBytesLength)
            } else {
                status = SecKeyDecrypt(processingSecKey, padding, plainBytes, plainBytesLength, cipherBytes, &cipherBytesLength)
            }
            
            if status == errSecSuccess {
                log("Successfully \(type == .encrypt ? "encrypted" : "decrypted") data with RSA key.")
                
                return cipherData.subdataWithRange(NSMakeRange(0, cipherBytesLength))
            } else {
                loge("Failed to \(type == .encrypt ? "encrypt" : "decrypt") data with RSA key.")
                return nil
            }
        } else {
            loge("Critical logic error at \(#function)")
            return nil
        }
    }
    
    // MARK: - Internal Utilities
    private func secKeyForTag(tag: String) -> SecKey? {
        var keyRef: AnyObject? = nil
        let query = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnData): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef,
            ]
        let status = SecItemCopyMatching(query, &keyRef)
        guard let secKey = keyRef as! SecKey? where status == errSecSuccess else {
            loge("Failed to retrieve key with result code: \(status), for tag: \(tag)")
            return nil
        }
        return secKey
    }
    
    private func keyDataForTag(tag: String) -> NSData? {
        var keyRef: AnyObject? = nil
        let query = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnData): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef,
            ]
        let status = SecItemCopyMatching(query, &keyRef)
        guard let keyData = keyRef as? NSData where status == errSecSuccess else {
            loge("Failed to retrieve key data with result code: \(status), for tag: \(tag)")
            return nil
        }
        return keyData
    }
    
    private func updateKey(tag: String, keyData: NSData?) -> Bool {
        
        let query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecClass): kSecClassKey as CFStringRef,
            String(kSecAttrApplicationTag): tag as CFStringRef]
        
        if let keyData = keyData {
            let status = SecItemUpdate(query, [String(kSecValueData): keyData])
            if status == errSecSuccess {
                log("Successfully updated key for tag: \(tag)")
                return true
            } else {
                loge("Failed to update key with result code: \(status), for tag: \(tag)")
                return false
            }
        } else {
            let status = SecItemDelete(query)
            if status == errSecSuccess {
                log("Successfully deleted key for tag: \(tag)")
                return true
            } else {
                loge("Failed to delete key with result code: \(status), for tag: \(tag)")
                return false
            }
        }
    }
}