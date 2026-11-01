// The vault: the KEKs of each flock sealed by the C library under the
// vault key, and the vault key itself encrypted (ECIES, P-256 +
// AES-GCM) to a key that lives in the Secure Enclave. That key never
// leaves it, is only usable with Face ID, Touch ID or the passcode for
// every single use and disappears together with the passcode. The
// platform never backs any of this up.
//
// Next to the KEKs we keep the backup recipient, a bookmark to the backup
// folder and the latest backup of each flock, "pending" until it is
// written to the backup folder.

import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum VaultError: Error, CustomStringConvertible {
    case cancelled
    case noPasscode
    case invalidated
    case missing(String)
    case failed(String)
    case core(Int)

    var code: String {
        switch self {
        case .cancelled: return "cancelled"
        case .noPasscode: return "nolock"
        case .invalidated: return "invalidated"
        case .missing: return "missing"
        case .failed: return "failed"
        case .core: return "core"
        }
    }

    var description: String {
        switch self {
        case .cancelled:
            return "Your keys were not unlocked."
        case .noPasscode:
            return "Set a passcode first, it protects your keys."
        case .invalidated:
            return "The passcode was removed, so the keys on this phone can no longer be opened."
        case .missing:
            return "The keys of this flock are not on this phone."
        case .failed(let why):
            return why
        case .core(let code):
            return "covenant core error \(code)"
        }
    }
}

final class Vault {
    static let shared = Vault()

    private static let tag = Data(((Bundle.main.bundleIdentifier ?? "") + ".vault").utf8)
    private static let algorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM
    private static let vkLength = 32

    private let dir: URL
    private let keyFile: URL
    private let levelFile: URL
    private let recipientFile: URL
    private let folderFile: URL

    private init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]

        dir = support.appendingPathComponent("vault", isDirectory: true)
        keyFile = dir.appendingPathComponent("vault.key")
        levelFile = dir.appendingPathComponent("vault.level")
        recipientFile = dir.appendingPathComponent("backup.recipient")
        folderFile = dir.appendingPathComponent("backup.folder")

        try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete])

        var url = dir
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    func info() -> [String: Any] {
        var flocks: [[String: Any]] = []
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []

        for name in files.sorted() where name.hasSuffix(".keks") {
            guard let data = try? Data(contentsOf: dir.appendingPathComponent(name)),
                  let info = Core.info(data) else { continue }

            let flock = String(format: "%016llx", info.flock)
            flocks.append(["flock": flock, "created": Int(info.created), "backup": backupState(flock)])
        }

        let backup: [String: Any] = [
            "key": FileManager.default.fileExists(atPath: recipientFile.path),
            "folder": folder().map { $0.lastPathComponent as Any } ?? NSNull(),
        ]

        let ready = FileManager.default.fileExists(atPath: keyFile.path)
        let level = (try? String(contentsOf: levelFile, encoding: .utf8)) ?? "none"

        return [
            "ready": ready,
            "invalidated": ready && !keyExists(),
            "hardware": ready ? level : "none",
            "auth": "Face ID, Touch ID or the passcode, every time",
            "flocks": flocks,
            "backup": backup,
        ]
    }

    func sealed(_ flock: String) throws -> Data {
        guard let data = try? Data(contentsOf: try flockFile(flock)) else {
            throw VaultError.missing(flock)
        }

        return data
    }

    func store(_ flock: String, _ sealed: Data) throws {
        try write(try flockFile(flock), sealed)
    }

    func has(_ flock: String) -> Bool {
        guard let file = try? flockFile(flock) else { return false }
        return FileManager.default.fileExists(atPath: file.path)
    }

    func remove(_ flock: String) throws {
        wipe(try flockFile(flock))
        dropBackup(flock)
    }

    func flocks() -> [String] {
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        return files.filter { $0.hasSuffix(".keks") }.map { String($0.dropLast(".keks".count)) }.sorted()
    }

    func recipient() -> Data? {
        try? Data(contentsOf: recipientFile)
    }

    func storeRecipient(_ recipient: Data) throws {
        try write(recipientFile, recipient)
    }

    func folder() -> URL? {
        guard let bookmark = try? Data(contentsOf: folderFile) else { return nil }

        var stale = false
        guard let url = try? URL(resolvingBookmarkData: bookmark, options: [], relativeTo: nil,
                                 bookmarkDataIsStale: &stale) else { return nil }

        if stale {
            try? storeFolder(url)
        }

        return url
    }

    func storeFolder(_ url: URL) throws {
        let bookmark = try BackupFolder.access(url) {
            try $0.bookmarkData(options: [], includingResourceValuesForKeys: nil, relativeTo: nil)
        }

        try write(folderFile, bookmark)
    }

    func storeBackup(_ flock: String, _ backup: Data, exported: Bool = false) throws {
        wipe(try backupFile(flock, ".backup"))
        wipe(try backupFile(flock, ".exported"))
        try write(try backupFile(flock, ".backup"), backup)

        if exported {
            try self.exported(flock)
        }
    }

    func dropBackup(_ flock: String) {
        guard let backup = try? backupFile(flock, ".backup"),
              let exported = try? backupFile(flock, ".exported") else { return }

        wipe(backup)
        wipe(exported)
    }

    func exported(_ flock: String) throws {
        try write(try backupFile(flock, ".exported"), Data())
    }

    /// The backups not written to the backup folder yet.
    func pending() -> [(String, Data)] {
        flocks().filter { backupState($0) == "pending" }.compactMap { (flock: String) -> (String, Data)? in
            guard let file = try? backupFile(flock, ".backup"),
                  let data = try? Data(contentsOf: file) else { return nil }
            return (flock, data)
        }
    }

    private func backupState(_ flock: String) -> String {
        guard let backup = try? backupFile(flock, ".backup"),
              let exported = try? backupFile(flock, ".exported") else { return "none" }

        if !FileManager.default.fileExists(atPath: backup.path) {
            return "none"
        }

        return FileManager.default.fileExists(atPath: exported.path) ? "exported" : "pending"
    }

    func wipeAll() {
        let files = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []

        for name in files {
            wipe(dir.appendingPathComponent(name))
        }

        deleteKey()
    }

    /// Ask for Face ID, Touch ID or the passcode and hand over the vault
    /// key, making the vault first when create is set and there is none.
    /// Blocks, never call it on the main thread. The caller wipes the key.
    func unlock(reason: String, create: Bool) throws -> [UInt8] {
        if !FileManager.default.fileExists(atPath: keyFile.path) {
            guard create else {
                throw VaultError.failed("There is no vault on this phone yet.")
            }

            return try make(reason: reason)
        }

        let wrapped = try Data(contentsOf: keyFile)
        let context = LAContext()
        context.localizedReason = reason

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Vault.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound {
            throw VaultError.invalidated
        }

        guard status == errSecSuccess, let found = item else {
            throw VaultError.failed("The vault key cannot be found (\(status)).")
        }

        let key = found as! SecKey
        var error: Unmanaged<CFError>?

        guard let plain = SecKeyCreateDecryptedData(key, Vault.algorithm, wrapped as CFData, &error) as Data? else {
            throw Vault.failure(error?.takeRetainedValue())
        }

        guard plain.count == Vault.vkLength else {
            throw VaultError.failed("The vault key file is damaged.")
        }

        return [UInt8](plain)
    }

    /// A new Secure Enclave key (or a keychain key on the simulator) and a
    /// new vault key encrypted to it.
    private func make(reason: String) throws -> [UInt8] {
        deleteKey()

        let enclave = SecureEnclave.isAvailable
        var error: Unmanaged<CFError>?

        let flags: SecAccessControlCreateFlags = enclave ? [.privateKeyUsage, .userPresence] : [.userPresence]

        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, &error) else {
            throw VaultError.failed("Cannot set up the vault key protection.")
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: Vault.tag,
                kSecAttrAccessControl as String: access,
            ] as [String: Any],
        ]

        if enclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let e = error?.takeRetainedValue()
            if let e = e, CFErrorGetCode(e) == Int(errSecAuthFailed) || CFErrorGetCode(e) == -25293 {
                throw VaultError.noPasscode
            }

            if !LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
                throw VaultError.noPasscode
            }

            throw VaultError.failed(e.map { "\($0)" } ?? "Cannot make the vault key.")
        }

        guard let pub = SecKeyCopyPublicKey(key) else {
            throw VaultError.failed("The vault key has no public half.")
        }

        var vk = [UInt8](repeating: 0, count: Vault.vkLength)
        let vkCount = vk.count
        guard SecRandomCopyBytes(kSecRandomDefault, vkCount, &vk) == errSecSuccess else {
            throw VaultError.failed("No random bytes for the vault key.")
        }

        let plain = Data(vk)
        guard let wrapped = SecKeyCreateEncryptedData(pub, Vault.algorithm, plain as CFData, &error) as Data? else {
            Core.wipe(&vk)
            throw Vault.failure(error?.takeRetainedValue())
        }

        try write(keyFile, wrapped)
        try write(levelFile, Data((enclave ? "secure-enclave" : "software").utf8))

        return vk
    }

    private func keyExists() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Vault.tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUISkip,
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)

        // Skipping the UI on a protected item still tells us it exists.
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    private func deleteKey() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Vault.tag,
        ]

        SecItemDelete(query as CFDictionary)
    }

    private static func failure(_ error: CFError?) -> VaultError {
        guard let error = error else {
            return .failed("The vault key could not be used.")
        }

        let code = CFErrorGetCode(error)

        // errSecUserCanceled and the LAError cancel codes.
        if code == Int(errSecUserCanceled) || code == LAError.userCancel.rawValue ||
            code == LAError.systemCancel.rawValue || code == LAError.appCancel.rawValue {
            return .cancelled
        }

        if code == LAError.passcodeNotSet.rawValue {
            return .noPasscode
        }

        return .failed(CFErrorCopyDescription(error) as String? ?? "The vault key could not be used.")
    }

    private func flockFile(_ flock: String) throws -> URL {
        guard flock.range(of: "^[0-9a-f]{16}$", options: .regularExpression) != nil else {
            throw VaultError.failed("invalid flock \(flock)")
        }

        return dir.appendingPathComponent(flock + ".keks")
    }

    private func backupFile(_ flock: String, _ suffix: String) throws -> URL {
        try flockFile(flock).deletingPathExtension().appendingPathExtension(String(suffix.dropFirst()))
    }

    private func write(_ url: URL, _ data: Data) throws {
        try data.write(to: url, options: [.atomic, .completeFileProtection])

        var target = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? target.setResourceValues(values)
    }

    private func wipe(_ url: URL) {
        guard let handle = try? FileHandle(forWritingTo: url) else { return }

        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? 0
        handle.write(Data(count: size))
        try? handle.synchronize()
        try? handle.close()

        try? FileManager.default.removeItem(at: url)
    }
}
