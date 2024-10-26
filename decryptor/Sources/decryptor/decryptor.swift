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
              let passwordData = existingItem[kSecValueData as String] as? Data
        else {
            print("Could not unpack password")
            return
        }
        do {
            let formatter = ISO8601DateFormatter()
            let filesURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/com.apple.icloud.searchpartyd/OwnedBeacons")
            let files = try FileManager.default.contentsOfDirectory(at: filesURL, includingPropertiesForKeys: nil)
            for url in files {
                let decrypted = decrypt(file: url, usingPassword:passwordData) as! [String:Any]
                let pairingDate = decrypted["pairingDate"] as! Date
                let id = decrypted["identifier"] as! String
                let name = findName(from: id, usingPassword: passwordData)
                let sharedSecret = ((((decrypted["sharedSecret"] as! [String:Any]) ["key"]) as! [String:Any]) ["data"]! as! Data).hexEncodedString()
                let publicKey = ((((decrypted["publicKey"] as! [String:Any]) ["key"]) as! [String:Any]) ["data"]! as! Data).hexEncodedString()
                print("\(formatter.string(from:pairingDate)) \(sharedSecret) \(publicKey) \(name)")
            }
        } catch {
            print(error)
        }
    }

    static func findName(from id:String, usingPassword passwordData:Data) -> String {
        let filesURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/com.apple.icloud.searchpartyd/BeaconNamingRecord/\(id)")
        do {
            let files = try FileManager.default.contentsOfDirectory(at: filesURL, includingPropertiesForKeys: nil)
            for url in files {
                let decrypted = decrypt(file: url, usingPassword:passwordData) as! [String:Any]
                if let emoji = decrypted["emoji"] {
                    return "\(decrypted["name"]!) (\(emoji))"
                }
                return decrypted["name"] as! String
            }
        } catch {
            // File doesnt exist
            return "Unknown device \(id)"
        }
        return "Unknown device \(id)"
    }

    static func decrypt(file url:URL, usingPassword passwordData:Data) -> Any {
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
            let plist = try! PropertyListSerialization.propertyList(from: decryptedData, options: [], format: nil)
            return plist
        }
        return []
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
