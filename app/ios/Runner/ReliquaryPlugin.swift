// Answers the user interface on the se.sanctorum.reliquary/core channel.
//
// The KEKs live sealed in the Vault, the session token in the keychain and
// the bookkeeping in our user defaults.

import Flutter
import Foundation
import Covenant
import Security
import UIKit
import UniformTypeIdentifiers
import UserNotifications

/// Thin wrappers around the C core, see include/covenant.h.
///
/// We keep one context for the whole app. Calls on it must not overlap,
/// so every call takes the lock and reads the error of the context right
/// after a call failed.
enum Core {
    static let sealedLength = 72 + 255 * 32 + 32 + 16
    static let sealedV1Length = 72 + 255 * 32 + 16
    static let ambryLength = 3_756_730
    static let coskLength = 32
    static let qrMax = 177 * 177
    static let configMax = 2048
    static let vaultKeyLength = 32
    static let rootLength = 32
    static let recipientLength = 1704
    static let backupLength = 1648 + 255 * 32 + 32 + 16 + 32
    static let backupV2Length = 1648 + 255 * 32 + 16 + 32

    static let parameter = 2
    static let recoveryKey = 14

    struct Info {
        let flock: UInt64
        let created: UInt64
    }

    struct BackupInfo {
        let flock: UInt64
        let made: UInt64
        let created: UInt64
    }

    private static let lock = NSLock()
    private static let ctx: OpaquePointer? = covenant_ctx_alloc()

    static func start() -> Bool { ctx != nil }

    static var version: String { String(cString: covenant_version()) }

    static func wipe(_ bytes: inout [UInt8]) {
        for idx in bytes.indices {
            bytes[idx] = 0
        }
    }

    private static func call(_ body: (OpaquePointer?) -> Int32) throws {
        lock.lock()
        defer { lock.unlock() }

        if body(ctx) == -1 {
            throw VaultError.core(Int(covenant_last_error(ctx)))
        }
    }

    private static func locked(_ body: (OpaquePointer?) -> Void) {
        lock.lock()
        defer { lock.unlock() }

        body(ctx)
    }

    static func info(_ sealed: Data) -> Info? {
        guard sealed.count == sealedLength || sealed.count == sealedV1Length else { return nil }

        var info = covenant_info()

        do {
            try sealed.withUnsafeBytes { raw in
                try call { covenant_keks_info($0, raw.baseAddress, raw.count, &info) }
            }
        } catch {
            return nil
        }

        return Info(flock: info.flock, created: info.created)
    }

    static func generate(_ vk: [UInt8], flock: UInt64) throws -> Data {
        var out = [UInt8](repeating: 0, count: sealedLength)
        let count = out.count

        locked { covenant_keks_generate($0, vk, vk.count, flock, &out, count) }

        return Data(out)
    }

    static func upgrade(_ vk: [UInt8], sealed: Data) throws -> Data {
        try sized(vk.count == vaultKeyLength, sealed.count == sealedV1Length)

        var out = [UInt8](repeating: 0, count: sealedLength)
        let input = [UInt8](sealed)
        let count = out.count

        try call {
            covenant_keks_upgrade($0, vk, vk.count, input, input.count, &out, count)
        }

        return Data(out)
    }

    static func renew(_ vk: [UInt8], sealed: Data, kek: UInt8) throws -> Data {
        guard sealed.count == sealedLength else { throw VaultError.core(parameter) }

        var out = [UInt8](repeating: 0, count: sealedLength)
        let input = [UInt8](sealed)
        let count = out.count

        try call {
            covenant_keks_renew($0, vk, vk.count, input, input.count, kek, &out, count)
        }

        return Data(out)
    }

    static func bundle(_ vk: [UInt8], sealed: Data, days: UInt16) throws -> [String: Any] {
        guard sealed.count == sealedLength else { throw VaultError.core(parameter) }

        var out = [UInt8](repeating: 0, count: ambryLength)
        var generation: UInt32 = 0
        var expires: UInt16 = 0
        let input = [UInt8](sealed)
        let count = out.count

        try call {
            covenant_ambry_bundle($0, vk, vk.count, input, input.count, days,
                             &out, count, &generation, &expires)
        }

        return [
            "bundle": FlutterStandardTypedData(bytes: Data(out)),
            "generation": Int(generation),
            "expires": Int(expires),
        ]
    }

    static func backupKeygen(_ vk: [UInt8], root: inout [UInt8]) throws -> Data {
        try sized(vk.count == vaultKeyLength, root.count == rootLength)

        var rcpt = [UInt8](repeating: 0, count: recipientLength)
        let rootCount = root.count
        let rcptCount = rcpt.count

        locked { covenant_backup_keygen($0, vk, vk.count, &root, rootCount, &rcpt, rcptCount) }

        return Data(rcpt)
    }

    static func backupRecipient(_ vk: [UInt8], root: [UInt8]) throws -> Data {
        try sized(vk.count == vaultKeyLength, root.count == rootLength)

        var rcpt = [UInt8](repeating: 0, count: recipientLength)
        let count = rcpt.count

        locked { covenant_backup_recipient($0, vk, vk.count, root, root.count, &rcpt, count) }

        return Data(rcpt)
    }

    static func backupVerify(root: [UInt8], recipient: Data) throws -> Bool {
        try sized(root.count == rootLength, recipient.count == recipientLength)

        let rcpt = [UInt8](recipient)

        do {
            try call { covenant_backup_verify($0, root, root.count, rcpt, rcpt.count) }
        } catch VaultError.core(let code) where code == recoveryKey {
            return false
        }

        return true
    }

    static func backupSeal(_ vk: [UInt8], recipient: Data, sealed: Data) throws -> Data {
        try sized(vk.count == vaultKeyLength, recipient.count == recipientLength,
                  sealed.count == sealedLength)

        var out = [UInt8](repeating: 0, count: backupLength)
        let rcpt = [UInt8](recipient)
        let input = [UInt8](sealed)
        let count = out.count

        try call {
            covenant_backup_seal($0, vk, vk.count, rcpt, rcpt.count, input, input.count, &out, count)
        }

        return Data(out)
    }

    static func backupRestore(_ vk: [UInt8], root: [UInt8], backup: Data) throws -> Data {
        try sized(vk.count == vaultKeyLength, root.count == rootLength,
                  backup.count == backupLength || backup.count == backupV2Length)

        var out = [UInt8](repeating: 0, count: sealedLength)
        let input = [UInt8](backup)
        let count = out.count

        try call {
            covenant_backup_restore($0, vk, vk.count, root, root.count, input, input.count, &out, count)
        }

        return Data(out)
    }

    static func backupInfo(_ backup: Data) -> BackupInfo? {
        guard backup.count == backupLength || backup.count == backupV2Length else { return nil }

        var info = covenant_backup_info()

        do {
            try backup.withUnsafeBytes { raw in
                try call { covenant_backup_info($0, raw.baseAddress, raw.count, &info) }
            }
        } catch {
            return nil
        }

        return BackupInfo(flock: info.flock, made: info.made, created: info.created)
    }

    private static func sized(_ checks: Bool...) throws {
        if checks.contains(false) {
            throw VaultError.core(parameter)
        }
    }

    static func cosk() throws -> [String: Any] {
        var handle: UInt32 = 0
        var pk = [UInt8](repeating: 0, count: coskLength)
        let count = pk.count

        try call { covenant_cosk_new($0, &handle, &pk, count) }

        return ["handle": Int(handle), "pk": FlutterStandardTypedData(bytes: Data(pk))]
    }

    static func coskDrop(_ handle: UInt32) {
        try? call { covenant_cosk_drop($0, handle) }
    }

    static func provision(_ vk: [UInt8], sealed: Data, kek: UInt8, handle: UInt32,
                          secret: String, config: String) throws -> [String: Any] {
        var qr = [UInt8](repeating: 0, count: qrMax)
        var side: Int32 = 0
        let input = [UInt8](sealed)
        let room = qr.count
        defer { wipe(&qr) }

        try vk.withUnsafeBytes { key in
            try input.withUnsafeBytes { keks in
                try secret.withCString { cs in
                    try config.withCString { cfg in
                        var dev = covenant_device()

                        dev.secret = key.baseAddress
                        dev.secret_len = key.count
                        dev.keks = keks.baseAddress
                        dev.keks_len = keks.count
                        dev.cathedral_secret = cs
                        dev.config = cfg
                        dev.cosk = handle
                        dev.kek = kek

                        try call { covenant_provision($0, &dev, &qr, room, &side) }
                    }
                }
            }
        }

        let count = Int(side) * Int(side)

        return ["side": Int(side), "modules": FlutterStandardTypedData(bytes: Data(qr[0..<count]))]
    }

    static func provisionConfig(_ vk: [UInt8], sealed: Data, kek: UInt8, handle: UInt32,
                                secret: String, config: String) throws -> [UInt8] {
        var out = [CChar](repeating: 0, count: configMax)
        let input = [UInt8](sealed)
        let room = out.count
        defer {
            for idx in out.indices {
                out[idx] = 0
            }
        }

        try vk.withUnsafeBytes { key in
            try input.withUnsafeBytes { keks in
                try secret.withCString { cs in
                    try config.withCString { cfg in
                        var dev = covenant_device()

                        dev.secret = key.baseAddress
                        dev.secret_len = key.count
                        dev.keks = keks.baseAddress
                        dev.keks_len = keks.count
                        dev.cathedral_secret = cs
                        dev.config = cfg
                        dev.cosk = handle
                        dev.kek = kek

                        try call { covenant_provision_config($0, &dev, &out, room) }
                    }
                }
            }
        }

        return out.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
    }
}

enum BackupFolder {
    private static let suffix = ".rlqb"
    private static let cloud = ".icloud"

    static func file(_ flock: String) -> String { "reliquary-\(flock)\(suffix)" }

    static func access<T>(_ dir: URL, _ body: (URL) throws -> T) throws -> T {
        let scoped = dir.startAccessingSecurityScopedResource()
        defer {
            if scoped {
                dir.stopAccessingSecurityScopedResource()
            }
        }

        return try body(dir)
    }

    static func write(_ dir: URL, _ name: String, _ data: Data) throws {
        try coordinate(writing: dir.appendingPathComponent(name)) { try data.write(to: $0) }
    }

    static func read(_ url: URL) throws -> Data {
        try coordinate(reading: url) { try Data(contentsOf: $0) }
    }

    /// The backups in the folder. iCloud Drive lists the ones it has not
    /// downloaded as .name.icloud.
    static func list(_ dir: URL) throws -> [URL] {
        var names = Set<String>()

        for name in try FileManager.default.contentsOfDirectory(atPath: dir.path) {
            if name.hasSuffix(suffix) && !name.hasPrefix(".") {
                names.insert(name)
            } else if name.hasPrefix(".") && name.hasSuffix(suffix + cloud) {
                names.insert(String(name.dropFirst().dropLast(cloud.count)))
            }
        }

        return names.sorted().map { dir.appendingPathComponent($0) }
    }

    private static func coordinate<T>(reading url: URL, _ body: (URL) throws -> T) throws -> T {
        var error: NSError?
        var result: Result<T, Error>?

        NSFileCoordinator().coordinate(readingItemAt: url, options: [], error: &error) { url in
            result = Result(catching: { try body(url) })
        }

        if let error = error {
            throw error
        }

        guard let result = result else {
            throw VaultError.failed("Could not read \(url.lastPathComponent).")
        }

        return try result.get()
    }

    private static func coordinate<T>(writing url: URL, _ body: (URL) throws -> T) throws -> T {
        var error: NSError?
        var result: Result<T, Error>?

        NSFileCoordinator().coordinate(writingItemAt: url, options: .forReplacing, error: &error) { url in
            result = Result(catching: { try body(url) })
        }

        if let error = error {
            throw error
        }

        guard let result = result else {
            throw VaultError.failed("Could not write \(url.lastPathComponent) to the backup folder.")
        }

        return try result.get()
    }
}

final class FolderPicker: NSObject, UIDocumentPickerDelegate {
    private let done: (URL?) -> Void

    init(_ done: @escaping (URL?) -> Void) {
        self.done = done
    }

    func present() -> Bool {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        var top = scenes.flatMap { $0.windows }.first { $0.isKeyWindow }?.rootViewController

        while let next = top?.presentedViewController {
            top = next
        }

        guard let top = top else { return false }

        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [UTType.folder])
        picker.delegate = self
        picker.allowsMultipleSelection = false
        top.present(picker, animated: true)

        return true
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        done(urls.first)
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        done(nil)
    }
}

enum Handoff {
    private static let url = URL(string: "vigil://import")!
    private static let service =
        Bundle.main.object(forInfoDictionaryKey: "CovenantHandoffGroup") as? String ?? ""

    private static var group: String {
        let prefix = Bundle.main.object(forInfoDictionaryKey: "AppIdentifierPrefix") as? String ?? ""
        return prefix + service
    }

    private static var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "config",
            kSecAttrAccessGroup as String: group,
        ]
    }

    static func available() -> Bool {
        UIApplication.shared.canOpenURL(url)
    }

    static func send(_ config: inout [UInt8]) throws {
        var data = Data(config)
        defer {
            Core.wipe(&config)
            data.resetBytes(in: 0..<data.count)
        }

        clear()

        var q = query
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        q[kSecAttrSynchronizable as String] = false

        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError.failed("Cannot hand the device to Vigil (\(status)).")
        }

        DispatchQueue.main.async {
            UIApplication.shared.open(Handoff.url) { opened in
                if !opened {
                    Handoff.clear()
                }
            }
        }
    }

    static func clear() {
        SecItemDelete(query as CFDictionary)
    }
}

final class Reminders: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Reminders()

    private static let prefix = "expiry-"

    private let lock = NSLock()
    private var reminded = ""

    func schedule(_ reminders: [[String: Any]]) {
        let center = UNUserNotificationCenter.current()

        center.getPendingNotificationRequests { pending in
            let old = pending.map { $0.identifier }.filter { $0.hasPrefix(Reminders.prefix) }
            center.removePendingNotificationRequests(withIdentifiers: old)

            for reminder in reminders {
                guard let flock = reminder["flock"] as? String,
                      let days = reminder["days"] as? Int,
                      let at = reminder["at"] as? Int else { continue }

                let date = Date(timeIntervalSince1970: TimeInterval(at) / 1000)
                let when = Calendar.current.dateComponents([.year, .month, .day, .hour, .minute], from: date)
                let left = days == 1 ? "1 day" : "\(days) days"
                let name = reminder["name"] as? String ?? flock

                let content = UNMutableNotificationContent()
                content.title = "Encrypted secrets expire soon"
                content.body = "The encrypted secrets of \(name) expire in \(left). Send new ones to keep its devices connected."
                content.sound = .default
                content.userInfo = ["flock": flock]

                center.add(UNNotificationRequest(
                    identifier: "\(Reminders.prefix)\(flock)-\(days)",
                    content: content,
                    trigger: UNCalendarNotificationTrigger(dateMatching: when, repeats: false)))
            }
        }
    }

    func allow() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func take() -> String {
        lock.lock()
        defer { lock.unlock() }

        let flock = reminded
        reminded = ""
        return flock
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        if let flock = response.notification.request.content.userInfo["flock"] as? String {
            lock.lock()
            reminded = flock
            lock.unlock()
        }

        completionHandler()
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter,
                                willPresent notification: UNNotification,
                                withCompletionHandler completionHandler:
                                    @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }
}

enum SessionStore {
    private static let service = (Bundle.main.bundleIdentifier ?? "") + ".session"

    private static var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "session",
        ]
    }

    static func load() -> String? {
        var q = query
        q[kSecReturnData as String] = true

        var item: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }

        return String(data: data, encoding: .utf8)
    }

    static func save(_ json: String) throws {
        clear()

        var q = query
        q[kSecValueData as String] = Data(json.utf8)
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError.failed("Cannot save the session (\(status)).")
        }
    }

    static func clear() {
        SecItemDelete(query as CFDictionary)
    }
}

final class ReliquaryPlugin: NSObject, FlutterPlugin {
    private static let channel = "se.sanctorum.reliquary/core"
    private static let prefsKey = "prefs"

    private let work = DispatchQueue(label: (Bundle.main.bundleIdentifier ?? "") + ".vault", qos: .userInitiated)
    private var picker: FolderPicker?

    static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: channel, binaryMessenger: registrar.messenger())

        if !Core.start() {
            NSLog("reliquary: the C library failed to start")
        }

        Handoff.clear()

        registrar.addMethodCallDelegate(ReliquaryPlugin(), channel: channel)
    }

    func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any] ?? [:]

        do {
            switch call.method {
            case "vault":
                background(result) { try self.json(Vault.shared.info()) }
            case "keksGenerate":
                let flock = try flockArg(args["flock"])
                let days = try daysArg(args["days"])

                withKey(result, "Set up the KEKs of your flock", create: true) { vk in
                    let sealed = try Core.generate(vk, flock: UInt64(flock, radix: 16)!)
                    let bundle = try Core.bundle(vk, sealed: sealed, days: days)

                    try Vault.shared.store(flock, sealed)
                    self.backup(vk, flock, sealed)
                    return bundle
                }
            case "keksRenew":
                let flock = try flockArg(args["flock"])
                let days = try daysArg(args["days"])
                let kek = try kekArg(args["kek"])
                let sealed = try Vault.shared.sealed(flock)

                withKey(result, "Replace the KEK of a removed device", create: false) { vk in
                    let renewed = try Core.renew(vk, sealed: self.upgraded(vk, flock, sealed), kek: kek)
                    let bundle = try Core.bundle(vk, sealed: renewed, days: days)

                    try Vault.shared.store(flock, renewed)
                    self.backup(vk, flock, renewed)
                    return bundle
                }
            case "bundle":
                let flock = try flockArg(args["flock"])
                let days = try daysArg(args["days"])
                let sealed = try Vault.shared.sealed(flock)

                withKey(result, "Make new encrypted secrets", create: false) { vk in
                    try Core.bundle(vk, sealed: self.upgraded(vk, flock, sealed), days: days)
                }
            case "keksDelete":
                try Vault.shared.remove(try flockArg(call.arguments))
                result("")
            case "backupKey":
                withKey(result, "Make a new recovery key", create: true) { vk in
                    var root = [UInt8](repeating: 0, count: Core.rootLength)
                    defer { Core.wipe(&root) }

                    try Vault.shared.storeRecipient(try Core.backupKeygen(vk, root: &root))
                    try self.backupAll(vk)

                    return FlutterStandardTypedData(bytes: Data(root))
                }
            case "backupAll":
                withKey(result, "Back up the KEKs of your flocks", create: false) { vk in
                    try self.backupAll(vk)
                    return ""
                }
            case "backupFolder":
                pickFolder(result)
            case "backupExport":
                background(result) { try self.export() }
            case "backupVerify":
                var root = try rootArg(call.arguments)

                background(result) {
                    defer { Core.wipe(&root) }

                    guard let recipient = Vault.shared.recipient() else {
                        throw VaultError.failed("There is no recovery key on this phone.")
                    }

                    return try Core.backupVerify(root: root, recipient: recipient)
                }
            case "backupScan":
                background(result) { try self.scan() }
            case "backupRestore":
                var root = try rootArg(call.arguments)

                withKey(result, "Restore your KEKs", create: true) { vk in
                    defer { Core.wipe(&root) }
                    return try self.restore(vk, root)
                }
            case "vaultWipe":
                Vault.shared.wipeAll()
                result("")
            case "coskNew":
                result(try Core.cosk())
            case "coskDrop":
                Core.coskDrop(UInt32(truncatingIfNeeded: (call.arguments as? Int) ?? 0))
                result("")
            case "provision":
                let flock = try flockArg(args["flock"])
                let kek = try kekArg(args["kek"])
                let handle = UInt32(truncatingIfNeeded: (args["handle"] as? Int) ?? 0)
                let secret = args["secret"] as? String ?? ""
                let config = args["config"] as? String ?? ""
                let sealed = try Vault.shared.sealed(flock)

                withKey(result, "Add a new device", create: false) { vk in
                    try Core.provision(vk, sealed: self.upgraded(vk, flock, sealed), kek: kek, handle: handle,
                                       secret: secret, config: config)
                }
            case "handoffAvailable":
                result(Handoff.available())
            case "handoff":
                let flock = try flockArg(args["flock"])
                let kek = try kekArg(args["kek"])
                let handle = UInt32(truncatingIfNeeded: (args["handle"] as? Int) ?? 0)
                let secret = args["secret"] as? String ?? ""
                let config = args["config"] as? String ?? ""
                let sealed = try Vault.shared.sealed(flock)

                withKey(result, "Add this phone to Vigil", create: false) { vk in
                    var full = try Core.provisionConfig(vk, sealed: self.upgraded(vk, flock, sealed),
                                                        kek: kek, handle: handle,
                                                        secret: secret, config: config)
                    try Handoff.send(&full)
                    return ""
                }
            case "reminders":
                Reminders.shared.schedule(call.arguments as? [[String: Any]] ?? [])
                result("")
            case "remindersAllow":
                Reminders.shared.allow()
                result("")
            case "remindedFlock":
                result(Reminders.shared.take())
            case "session":
                result(SessionStore.load())
            case "sessionSave":
                try SessionStore.save(call.arguments as? String ?? "{}")
                result("")
            case "sessionClear":
                SessionStore.clear()
                result("")
            case "prefs":
                result(UserDefaults.standard.string(forKey: ReliquaryPlugin.prefsKey) ?? "{}")
            case "prefsSave":
                UserDefaults.standard.set(call.arguments as? String ?? "{}", forKey: ReliquaryPlugin.prefsKey)
                result("")
            case "version":
                result(Core.version)
            default:
                result(FlutterMethodNotImplemented)
            }
        } catch {
            result(flutterError(error))
        }
    }

    private func upgraded(_ vk: [UInt8], _ flock: String, _ sealed: Data) throws -> Data {
        guard sealed.count == Core.sealedV1Length else { return sealed }

        let upgraded = try Core.upgrade(vk, sealed: sealed)
        try Vault.shared.store(flock, upgraded)
        backup(vk, flock, upgraded)

        return upgraded
    }

    private func backup(_ vk: [UInt8], _ flock: String, _ sealed: Data) {
        guard let recipient = Vault.shared.recipient() else { return }

        Vault.shared.dropBackup(flock)

        do {
            try Vault.shared.storeBackup(flock, try Core.backupSeal(vk, recipient: recipient, sealed: sealed))
        } catch {
            NSLog("reliquary: failed to back up \(flock): \(error)")
            return
        }

        exportQuietly()
    }

    private func backupAll(_ vk: [UInt8]) throws {
        guard let recipient = Vault.shared.recipient() else {
            throw VaultError.failed("Make a recovery key first.")
        }

        for flock in Vault.shared.flocks() {
            let sealed = try upgraded(vk, flock, try Vault.shared.sealed(flock))
            try Vault.shared.storeBackup(flock, try Core.backupSeal(vk, recipient: recipient, sealed: sealed))
        }

        exportQuietly()
    }

    private func export() throws -> Int {
        guard let folder = Vault.shared.folder() else { return 0 }

        return try BackupFolder.access(folder) { dir in
            var count = 0

            for (flock, backup) in Vault.shared.pending() {
                try BackupFolder.write(dir, BackupFolder.file(flock), backup)
                try Vault.shared.exported(flock)
                count += 1
            }

            return count
        }
    }

    private func exportQuietly() {
        do {
            _ = try export()
        } catch {
            NSLog("reliquary: failed to export backups: \(error)")
        }
    }

    private func pickFolder(_ result: @escaping FlutterResult) {
        picker = nil

        let picker = FolderPicker { url in
            self.picker = nil

            guard let url = url else {
                result(nil)
                return
            }

            self.background(result) {
                try Vault.shared.storeFolder(url)
                _ = try self.export()
                return url.lastPathComponent
            }
        }

        guard picker.present() else {
            result(FlutterError(code: "failed", message: "Cannot show the folder picker.", details: nil))
            return
        }

        self.picker = picker
    }

    private func scan() throws -> [[String: Any]] {
        guard let folder = Vault.shared.folder() else {
            throw VaultError.failed("Choose the folder with your backups first.")
        }

        return try BackupFolder.access(folder) { dir in
            try BackupFolder.list(dir).compactMap { (url: URL) throws -> [String: Any]? in
                guard let info = Core.backupInfo(try BackupFolder.read(url)) else { return nil }
                let flock = String(format: "%016llx", info.flock)

                return [
                    "flock": flock,
                    "made": Int(info.made),
                    "created": Int(info.created),
                    "here": Vault.shared.has(flock),
                ]
            }.sorted { ($0["flock"] as! String) < ($1["flock"] as! String) }
        }
    }

    /// Restore every flock in the backup folder that this phone has no KEKs
    /// for. Without a recipient of its own this phone takes on the one of
    /// the given recovery key.
    private func restore(_ vk: [UInt8], _ root: [UInt8]) throws -> [String: Any] {
        guard let folder = Vault.shared.folder() else {
            throw VaultError.failed("Choose the folder with your backups first.")
        }

        var restored: [String] = []
        var skipped: [String] = []
        var failed: [String] = []

        try BackupFolder.access(folder) { dir in
            for url in try BackupFolder.list(dir) {
                let backup = try BackupFolder.read(url)
                guard let info = Core.backupInfo(backup) else { continue }
                let flock = String(format: "%016llx", info.flock)

                if Vault.shared.has(flock) {
                    skipped.append(flock)
                    continue
                }

                let sealed: Data

                do {
                    sealed = try Core.backupRestore(vk, root: root, backup: backup)
                } catch VaultError.core(let code) where code == Core.recoveryKey {
                    failed.append(flock)
                    continue
                }

                try Vault.shared.store(flock, sealed)
                try Vault.shared.storeBackup(flock, backup, exported: true)
                restored.append(flock)
            }
        }

        if restored.isEmpty && !failed.isEmpty {
            throw VaultError.core(Core.recoveryKey)
        }

        if let recipient = Vault.shared.recipient() {
            if try !Core.backupVerify(root: root, recipient: recipient) {
                for flock in restored {
                    let sealed = try Vault.shared.sealed(flock)
                    try Vault.shared.storeBackup(flock, try Core.backupSeal(vk, recipient: recipient, sealed: sealed))
                }
                exportQuietly()
            }
        } else if !restored.isEmpty {
            try Vault.shared.storeRecipient(try Core.backupRecipient(vk, root: root))
        }

        return ["restored": restored, "skipped": skipped, "failed": failed]
    }

    private func withKey(_ result: @escaping FlutterResult, _ reason: String, create: Bool,
                         _ body: @escaping ([UInt8]) throws -> Any?) {
        background(result) {
            var vk = try Vault.shared.unlock(reason: reason, create: create)
            defer { Core.wipe(&vk) }

            return try body(vk)
        }
    }

    private func background(_ result: @escaping FlutterResult, _ body: @escaping () throws -> Any?) {
        work.async {
            let reply: Any?

            do {
                reply = try body()
            } catch {
                reply = self.flutterError(error)
            }

            DispatchQueue.main.async { result(reply) }
        }
    }

    private func flutterError(_ error: Error) -> FlutterError {
        if case .core(let code) = error as? VaultError {
            return FlutterError(code: "core", message: "covenant core error \(code)", details: code)
        }

        if let v = error as? VaultError {
            return FlutterError(code: v.code, message: v.description, details: nil)
        }

        return FlutterError(code: "failed", message: "\(error)", details: nil)
    }

    private func json(_ object: Any) throws -> String {
        String(data: try JSONSerialization.data(withJSONObject: object), encoding: .utf8) ?? "{}"
    }

    private func flockArg(_ value: Any?) throws -> String {
        guard let flock = value as? String,
              flock.range(of: "^[0-9a-f]{16}$", options: .regularExpression) != nil else {
            throw VaultError.failed("That is not a flock ID.")
        }

        return flock
    }

    private func daysArg(_ value: Any?) throws -> UInt16 {
        guard let days = value as? Int, (1...3650).contains(days) else {
            throw VaultError.failed("Encrypted secrets last 1 to 3650 days.")
        }

        return UInt16(days)
    }

    private func rootArg(_ value: Any?) throws -> [UInt8] {
        guard let data = value as? FlutterStandardTypedData, data.data.count == Core.rootLength else {
            throw VaultError.failed("A recovery key is 64 letters and digits, check it again.")
        }

        return [UInt8](data.data)
    }

    private func kekArg(_ value: Any?) throws -> UInt8 {
        guard let kek = value as? Int, (1...255).contains(kek) else {
            throw VaultError.failed("KEK IDs are 01 to ff.")
        }

        return UInt8(kek)
    }
}
