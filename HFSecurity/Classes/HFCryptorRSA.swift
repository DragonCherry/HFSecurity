//
//  HFCryptorRSA.swift
//  Pods
//
//  Created by DragonCherry on 6/30/16.
//
//

import CoreFoundation
import Security
import RNCryptor
import TinyLog

open class HFCryptorRSA {
    
    fileprivate let kTemporaryKeyTag: String = "kTemporaryKeyTag"
    
    fileprivate enum HFCryptorRSAProcessType {
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
    fileprivate var privateTag: String!
    fileprivate var privateSecKey: SecKey? = nil
    open var privateKey: Data? {
        return keyData(forTag: privateTag)
    }
    
    // MARK: - Public Key
    fileprivate var publicTag: String!
    fileprivate var publicSecKey: SecKey? = nil
    open var publicKey: Data? {
        return keyData(forTag: publicTag)
    }
    
    // MARK: - Initializer
    public init(privateTag: String, publicTag: String) {
        self.privateSecKey = self.secKey(forTag: privateTag)
        self.privateTag = privateTag
        self.publicSecKey = self.secKey(forTag: publicTag)
        self.publicTag = publicTag
    }
    
    // MARK: - API
    open func generateKeyPair(_ size: HFCryptorRSAKeySize = .bits2048, writeOnKeychain: Bool = false, regenerate: Bool = false) -> Bool {
        
        keySize = size
        
        // clear if regeneration flag is on
        if regenerate {
            updateKey(privateTag, keyData: nil)
            updateKey(publicTag, keyData: nil)
        }
        
        // set option for private key
        let privateAttributes = [
            String(kSecAttrIsPermanent): writeOnKeychain,
            String(kSecAttrCanEncrypt): false,
            String(kSecAttrCanDecrypt): true,
            String(kSecAttrCanSign): true,
            String(kSecAttrCanVerify): false,
            String(kSecAttrApplicationTag): self.privateTag
        ] as [String : Any]
        
        // set option for public key
        let publicAttributes = [
            String(kSecAttrIsPermanent): writeOnKeychain,
            String(kSecAttrCanEncrypt): true,
            String(kSecAttrCanDecrypt): false,
            String(kSecAttrCanSign): false,
            String(kSecAttrCanVerify): true,
            String(kSecAttrApplicationTag): self.publicTag
        ] as [String : Any]
        
        // set option for key pair
        let pairAttributes = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecAttrKeySizeInBits): size.rawValue,
            String(kSecPublicKeyAttrs): publicAttributes,
            String(kSecPrivateKeyAttrs): privateAttributes
        ] as [String : Any]
        
        // generate key pair
        let status = SecKeyGeneratePair(pairAttributes as CFDictionary, &publicSecKey, &privateSecKey)
        if errSecSuccess == status {
            log("Successfully generated key pair on \(writeOnKeychain ? "keychain" : "memory") with size of \(size.rawValue) bit.")
            log("[Private Key] \(keyData(forTag: privateTag)?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0)) ?? "Fail")")
            log("[Public Key] \(keyData(forTag: publicTag)?.base64EncodedString(options: NSData.Base64EncodingOptions(rawValue: 0)) ?? "Fail")")
            return true
        } else {
            loge("Failed to generate RSA key pair with code: \(status)")
            return false
        }
    }
    
    /// encrypt
    open func encrypt(_ data: Data, key: Data? = nil, padding: SecPadding = SecPadding()) -> Data? {
        return process(data, type: .encrypt, key: key, padding: padding)
    }
    
    open func decrypt(_ data: Data, key: Data? = nil, padding: SecPadding = SecPadding()) -> Data? {
        return process(data, type: .decrypt, key: key, padding: padding)
    }
    
    /// encrypt or decrypt data with given key
    fileprivate func process(_ data: Data, type: HFCryptorRSAProcessType, key: Data? = nil, padding: SecPadding = SecPadding()) -> Data? {
        
        var processingSecKey: SecKey? = nil
        
        // log data size
        log("Data size to process: \(data.count), key size: \(self.keySize.rawValue)")
        
        if type == .encrypt {
            guard data.count < (self.keySize.rawValue / 8) else {
                loge("Data size exceeds its limit.")
                return nil
            }
        }
        
        // save public key data on temporary space in keychain and retrieve it as SecKey type if it has designated key
        if let designatedKey = key {
            
            if self.updateKey(kTemporaryKeyTag, keyData: designatedKey) {
                
                // check key first
                guard let designatedSecKey = secKey(forTag: kTemporaryKeyTag) else {
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
            let plainBytes = (data as NSData).bytes.bindMemory(to: UInt8.self, capacity: data.count)
            let plainBytesLength = data.count
            
            var cipherBytesLength = SecKeyGetBlockSize(processingSecKey)
            
            guard let cipherData = NSMutableData(length: cipherBytesLength) else {
                log("Failed to allocate NSMutableData with length \(cipherBytesLength)")
                return nil
            }
            
            let cipherBytes = cipherData.mutableBytes.assumingMemoryBound(to: UInt8.self)
            
            var status = errSecSuccess
            if type == .encrypt {
                status = SecKeyEncrypt(processingSecKey, padding, plainBytes, plainBytesLength, cipherBytes, &cipherBytesLength)
            } else {
                status = SecKeyDecrypt(processingSecKey, padding, plainBytes, plainBytesLength, cipherBytes, &cipherBytesLength)
            }
            
            if status == errSecSuccess {
                log("Successfully \(type == .encrypt ? "encrypted" : "decrypted") data with RSA key.")
                
                return cipherData.subdata(with: NSMakeRange(0, cipherBytesLength))
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
    fileprivate func secKey(forTag tag: String) -> SecKey? {
        var keyRef: AnyObject? = nil
        let query = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnData): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFString,
            String(kSecAttrApplicationTag): tag as CFString,
            ] as [String : Any]
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
        guard let secKey = keyRef as! SecKey?, status == errSecSuccess else {
            loge("Failed to retrieve key with result code: \(status), for tag: \(tag)")
            return nil
        }
        return secKey
    }
    
    fileprivate func keyData(forTag tag: String) -> Data? {
        var keyRef: AnyObject? = nil
        let query = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecReturnData): kCFBooleanTrue as CFBoolean,
            String(kSecClass): kSecClassKey as CFString,
            String(kSecAttrApplicationTag): tag as CFString,
            ] as [String : Any]
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
        guard let keyData = keyRef as? Data, status == errSecSuccess else {
            loge("Failed to retrieve key data with result code: \(status), for tag: \(tag)")
            return nil
        }
        return keyData
    }
    
    @discardableResult
    fileprivate func updateKey(_ tag: String, keyData: Data?) -> Bool {
        
        let query: Dictionary<String, AnyObject> = [
            String(kSecAttrKeyType): kSecAttrKeyTypeRSA,
            String(kSecClass): kSecClassKey as CFString,
            String(kSecAttrApplicationTag): tag as CFString]
        
        if let keyData = keyData {
            let status = SecItemUpdate(query as CFDictionary, [String(kSecValueData): keyData] as CFDictionary)
            if status == errSecSuccess {
                log("Successfully updated key for tag: \(tag)")
                return true
            } else {
                loge("Failed to update key with result code: \(status), for tag: \(tag)")
                return false
            }
        } else {
            let status = SecItemDelete(query as CFDictionary)
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
