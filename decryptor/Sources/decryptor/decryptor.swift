import CryptoKit
import Foundation
import Security

@main
public struct decryptor {
    public static func main() {

        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: "BeaconStore",
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            print("Failed to retrieve BeaconStore password")
            return
        }
        guard let existingItem = item as? [String : Any],
              let passwordData = existingItem[kSecAttrGeneric as String] as? Data
        else {
            print("Could not unpack password")
            return
        }
        do {
            let formatter = ISO8601DateFormatter()
            let filesURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/com.apple.icloud.searchpartyd/OwnedBeacons")
            let files = try FileManager.default.contentsOfDirectory(at: filesURL, includingPropertiesForKeys: nil)
            for url in files {
                let isAccessing = url.startAccessingSecurityScopedResource()
                let recordData = try! Data(contentsOf: url)
                if (isAccessing) {
                    url.stopAccessingSecurityScopedResource()
                }
                if let arr = try! PropertyListSerialization.propertyList(from: recordData, options: [], format: nil) as? [Any] {
                    let nonce = arr[0] as! NSData
                    let tag = arr[1] as! NSData
                    let ciphertext = arr[2] as! NSData
                    let sealedBox = try! AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                                                        ciphertext: ciphertext,
                                                        tag: tag)
                    let key = SymmetricKey(data: passwordData)
                    let decryptedData = try! AES.GCM.open(sealedBox, using: key)
                    if let decrypted = try! PropertyListSerialization.propertyList(from: decryptedData, options: [], format: nil) as? [String:Any] {
                        let pairingDate = decrypted["pairingDate"] as! Date
                        let id = decrypted["identifier"] as! String
                        let sharedSecret = ((((decrypted["sharedSecret"] as! [String:Any]) ["key"]) as! [String:Any]) ["data"]! as! Data).hexEncodedString()
                        let privateKey = ((((decrypted["privateKey"] as! [String:Any]) ["key"]) as! [String:Any]) ["data"]! as! Data).hexEncodedString()
                        print("\(formatter.string(from:pairingDate)) \(sharedSecret) \(privateKey) Device \(id)")
                    }
                }

            }
        } catch {
            print(error)
        }
    }
}

extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let format = options.contains(.upperCase) ? "%02hhX" : "%02hhx"
        return self.map { String(format: format, $0) }.joined()
    }
}