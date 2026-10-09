import Foundation
import SwiftUI
import CryptoKit
import CommonCrypto
import LocalAuthentication
import Security
import UIKit
import UniformTypeIdentifiers

private let midnight = Color(hex: 0x0B0F14)
private let slate = Color(hex: 0x121826)
private let slate2 = Color(hex: 0x172033)
private let cyan = Color(hex: 0x00E5D1)
private let ice = Color(hex: 0x7DD3FC)
private let indigo = Color(hex: 0x6366F1)
private let muted = Color(hex: 0xAABBD5)
private let good = Color(hex: 0x22E3B0)
private let warn = Color(hex: 0xFFC247)
private let danger = Color(hex: 0xFF5B6E)

extension View {
    func keyraPageWidth(_ width: CGFloat = 900) -> some View {
        frame(maxWidth: width)
            .frame(maxWidth: .infinity)
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xff) / 255,
            green: Double((hex >> 8) & 0xff) / 255,
            blue: Double(hex & 0xff) / 255,
            opacity: 1
        )
    }
}

struct TotpConfig {
    let secret: String
    let issuer: String
    let account: String
    let algorithm: String
    let digits: Int
    let period: Int
}

private let base32Alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

func normalizedBase32Secret(_ raw: String) -> String? {
    guard raw.count <= 2_048 else { return nil }
    let encoded = raw
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .uppercased()
        .filter { $0 != " " && $0 != "-" }

    guard let decoded = decodeBase32(encoded), !decoded.isEmpty else { return nil }
    return String(encoded.prefix { $0 != "=" })
}

func decodeBase32(_ raw: String) -> Data? {
    guard raw.count <= 1_024 else { return nil }
    let encoded = raw.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
    let clean = String(encoded.prefix { $0 != "=" })
    let allowed = Set(base32Alphabet)
    guard !clean.isEmpty, clean.allSatisfy({ allowed.contains($0) }) else { return nil }
    let remainder = clean.count % 8
    guard [0, 2, 4, 5, 7].contains(remainder) else { return nil }
    let padding = encoded.count - clean.count
    guard encoded.dropFirst(clean.count).allSatisfy({ $0 == "=" }) else { return nil }
    let expectedPadding: Int
    switch remainder {
    case 2: expectedPadding = 6
    case 4: expectedPadding = 4
    case 5: expectedPadding = 3
    case 7: expectedPadding = 1
    default: expectedPadding = 0
    }
    if padding > 0 && (encoded.count % 8 != 0 || padding != expectedPadding) {
        return nil
    }

    let table = Dictionary(uniqueKeysWithValues: base32Alphabet.enumerated().map { ($0.element, $0.offset) })
    var output = [UInt8]()
    var buffer = 0
    var bits = 0

    for char in clean {
        guard let value = table[char] else { return nil }
        buffer = (buffer << 5) | value
        bits += 5

        while bits >= 8 {
            bits -= 8
            output.append(UInt8((buffer >> bits) & 0xFF))
            buffer = bits == 0 ? 0 : buffer & ((1 << bits) - 1)
        }
    }

    // RFC 4648 requires any remaining unused bits to be zero.
    guard buffer == 0 else { return nil }
    return Data(output)
}

private func normalizedTotpAlgorithm(_ raw: String) -> String? {
    switch raw.trimmingCharacters(in: .whitespacesAndNewlines).uppercased().replacingOccurrences(of: "-", with: "") {
    case "SHA1": return "SHA1"
    case "SHA256": return "SHA256"
    case "SHA512": return "SHA512"
    default: return nil
    }
}

func parseTotpInput(
    _ raw: String,
    fallbackIssuer: String = "",
    fallbackAccount: String = "",
    fallbackAlgorithm: String = "SHA1",
    fallbackDigits: Int = 6,
    fallbackPeriod: Int = 30
) -> TotpConfig? {
    let input = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !input.isEmpty, input.count <= 4_096 else { return nil }

    if !input.lowercased().hasPrefix("otpauth://") {
        guard let secret = normalizedBase32Secret(input) else { return nil }
        guard let algorithm = normalizedTotpAlgorithm(fallbackAlgorithm),
              (6...8).contains(fallbackDigits),
              (15...120).contains(fallbackPeriod) else { return nil }
        let digits = fallbackDigits
        let period = fallbackPeriod
        return TotpConfig(
            secret: secret,
            issuer: fallbackIssuer.trimmingCharacters(in: .whitespacesAndNewlines),
            account: fallbackAccount.trimmingCharacters(in: .whitespacesAndNewlines),
            algorithm: algorithm,
            digits: digits,
            period: period
        )
    }

    guard
        let components = URLComponents(string: input),
        components.scheme?.lowercased() == "otpauth",
        components.host?.lowercased() == "totp",
        components.user == nil,
        components.password == nil,
        components.port == nil,
        components.fragment == nil
    else {
        return nil
    }

    var params: [String: String] = [:]
    for item in components.queryItems ?? [] {
        let key = item.name.lowercased()
        guard !key.isEmpty, params[key] == nil, let value = item.value else { return nil }
        params[key] = value
    }
    guard let secret = normalizedBase32Secret(params["secret"] ?? "") else { return nil }

    let rawLabel = components.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
    let label = rawLabel.removingPercentEncoding ?? rawLabel
    let labelParts = label.split(separator: ":", maxSplits: 1).map(String.init)
    let labelIssuer = labelParts.count == 2 ? labelParts[0].trimmingCharacters(in: .whitespacesAndNewlines) : ""
    let labelAccount = labelParts.count == 2
        ? labelParts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        : label.trimmingCharacters(in: .whitespacesAndNewlines)

    let issuer = (params["issuer"] ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
    let resolvedIssuer = issuer.isEmpty
        ? (fallbackIssuer.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? labelIssuer
            : fallbackIssuer.trimmingCharacters(in: .whitespacesAndNewlines))
        : issuer
    let fallbackAccountValue = fallbackAccount.trimmingCharacters(in: .whitespacesAndNewlines)
    let resolvedAccount = fallbackAccountValue.isEmpty ? labelAccount : fallbackAccountValue

    guard let algorithm = normalizedTotpAlgorithm(params["algorithm"] ?? fallbackAlgorithm) else {
        return nil
    }
    if let rawDigits = params["digits"], Int(rawDigits) == nil { return nil }
    if let rawPeriod = params["period"], Int(rawPeriod) == nil { return nil }
    let digits = Int(params["digits"] ?? "") ?? fallbackDigits
    let period = Int(params["period"] ?? "") ?? fallbackPeriod
    guard (6...8).contains(digits), (15...120).contains(period) else { return nil }

    return TotpConfig(
        secret: secret,
        issuer: resolvedIssuer,
        account: resolvedAccount,
        algorithm: algorithm,
        digits: digits,
        period: period
    )
}

func generateTotp(
    _ config: TotpConfig,
    at date: Date = Date()
) -> String? {
    let timestamp = date.timeIntervalSince1970
    guard timestamp.isFinite, timestamp >= 0,
          timestamp < Double(UInt64.max),
          (15...120).contains(config.period),
          (6...8).contains(config.digits),
          let algorithm = normalizedTotpAlgorithm(config.algorithm),
          let secret = decodeBase32(config.secret), !secret.isEmpty else { return nil }

    let counter = UInt64(timestamp) / UInt64(config.period)
    var bigEndianCounter = counter.bigEndian
    let counterData = withUnsafeBytes(of: &bigEndianCounter) { Data($0) }
    let key = SymmetricKey(data: secret)

    let hash: [UInt8]
    switch algorithm {
    case "SHA256":
        hash = Array(HMAC<SHA256>.authenticationCode(for: counterData, using: key))
    case "SHA512":
        hash = Array(HMAC<SHA512>.authenticationCode(for: counterData, using: key))
    case "SHA1":
        hash = Array(HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key))
    default:
        return nil
    }

    guard let last = hash.last else { return nil }
    let offset = Int(last & 0x0F)
    guard offset + 3 < hash.count else { return nil }

    let binary =
        (Int(hash[offset] & 0x7F) << 24) |
        (Int(hash[offset + 1]) << 16) |
        (Int(hash[offset + 2]) << 8) |
        Int(hash[offset + 3])

    var modulo = 1
    for _ in 0..<config.digits { modulo *= 10 }
    return String(format: "%0*d", config.digits, binary % modulo)
}

func totpRemainingSeconds(
    _ config: TotpConfig,
    at date: Date = Date()
) -> Int {
    let timestamp = date.timeIntervalSince1970
    guard timestamp.isFinite, timestamp >= 0,
          timestamp < Double(Int.max),
          (15...120).contains(config.period),
          (6...8).contains(config.digits) else { return 0 }
    let seconds = Int(timestamp)
    return config.period - (seconds % config.period)
}

func totpConfigFromFields(_ fields: [String: String]) -> TotpConfig? {
    guard let secret = fields["TOTP tajna"] else { return nil }
    if let rawDigits = fields["Znamenke"], Int(rawDigits) == nil { return nil }
    if let rawPeriod = fields["Period"], Int(rawPeriod) == nil { return nil }
    let rawAlgorithm = fields["Algoritam"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    return parseTotpInput(
        secret,
        fallbackIssuer: fields["Izdavatelj"] ?? "",
        fallbackAccount: fields["Račun"] ?? "",
        fallbackAlgorithm: rawAlgorithm.isEmpty ? "SHA1" : rawAlgorithm,
        fallbackDigits: Int(fields["Znamenke"] ?? "") ?? 6,
        fallbackPeriod: Int(fields["Period"] ?? "") ?? 30
    )
}

func formatTotpCode(_ code: String) -> String {
    if code.count == 6 {
        return String(code.prefix(3)) + " " + String(code.suffix(3))
    }
    if code.count == 8 {
        return String(code.prefix(4)) + " " + String(code.suffix(4))
    }
    return code
}

func normalizedCardDigits(_ raw: String) -> String? {
    let asciiDigits = Set("0123456789")
    guard raw.allSatisfy({ asciiDigits.contains($0) || $0 == " " || $0 == "-" }) else { return nil }
    return String(raw.filter { asciiDigits.contains($0) })
}

func formatCardNumberInput(_ raw: String) -> String {
    let asciiDigits = Set("0123456789")
    let digits = Array(raw.filter { asciiDigits.contains($0) }.prefix(19))
    return stride(from: 0, to: digits.count, by: 4)
        .map { String(digits[$0..<min($0 + 4, digits.count)]) }
        .joined(separator: " ")
}

func isValidCardSecurityCode(_ raw: String) -> Bool {
    let asciiDigits = Set("0123456789")
    return (3...4).contains(raw.count) && raw.allSatisfy { asciiDigits.contains($0) }
}

func isValidCardNumber(_ raw: String) -> Bool {
    guard let normalized = normalizedCardDigits(raw) else { return false }
    let digits = normalized.compactMap(\.wholeNumberValue)
    guard (12...19).contains(digits.count) else { return false }
    guard Set(digits).count >= 2 else { return false }

    var sum = 0
    var shouldDouble = false
    for digit in digits.reversed() {
        var value = digit
        if shouldDouble {
            value *= 2
            if value > 9 { value -= 9 }
        }
        sum += value
        shouldDouble.toggle()
    }
    return sum.isMultiple(of: 10)
}

func isCardExpiryNotPast(
    _ raw: String,
    now: Date = Date(),
    calendar: Calendar = .current
) -> Bool {
    let parts = raw.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "/")
    guard
        parts.count == 2,
        let month = Int(parts[0]),
        (1...12).contains(month),
        let parsedYear = Int(parts[1]),
        parts[1].count == 2 || parts[1].count == 4
    else {
        return false
    }

    let year = parts[1].count == 2 ? 2000 + parsedYear : parsedYear
    let currentYear = calendar.component(.year, from: now)
    let currentMonth = calendar.component(.month, from: now)
    return year > currentYear || (year == currentYear && month >= currentMonth)
}

func formatCardExpiry(_ raw: String) -> String {
    let digits = raw.filter(\.isNumber).prefix(6)
    guard digits.count > 2 else { return String(digits) }
    let month = digits.prefix(2)
    let year = digits.dropFirst(2)
    return "\(month)/\(year)"
}

func normalizedWebURL(_ raw: String) -> URL? {
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return nil }

    let candidate: String
    if trimmed.lowercased().hasPrefix("https://") || trimmed.lowercased().hasPrefix("http://") {
        candidate = trimmed
    } else {
        candidate = "https://" + trimmed
    }

    guard
        let components = URLComponents(string: candidate),
        let scheme = components.scheme?.lowercased(),
        ["https", "http"].contains(scheme),
        let host = components.host,
        !host.isEmpty
    else {
        return nil
    }
    return components.url
}

// Imported document providers may expose very large files. Enforce the byte limit
// before decoding instead of mapping the entire untrusted document into memory.
private enum KeyraDocumentError: Error { case invalidOrOversized }

func readLimitedKeyraText(_ url: URL, maxBytes: Int) throws -> String {
    guard maxBytes > 0 else { throw KeyraDocumentError.invalidOrOversized }
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var data = Data()
    while data.count <= maxBytes {
        let next = try handle.read(upToCount: min(8192, maxBytes + 1 - data.count)) ?? Data()
        if next.isEmpty { break }
        data.append(next)
    }
    guard data.count <= maxBytes, let text = String(data: data, encoding: .utf8) else {
        throw KeyraDocumentError.invalidOrOversized
    }
    return text
}

enum SecureClipboard {
    static func copy(_ text: String) {
        UIPasteboard.general.setItems(
            [[UTType.plainText.identifier: text]],
            options: [
                .localOnly: true,
                .expirationDate: Date().addingTimeInterval(30)
            ]
        )
    }
}

enum KeyraScreen: Equatable {
    case onboarding, recovery, unlock, vault, collections, generator, add, detail, settings, security
}

struct VaultItem: Identifiable, Codable, Equatable {
    var id = UUID()
    var title: String
    var username = ""
    var password = ""
    var website = ""
    var notes = ""
    var category = "Osobno"
    var favorite = false
    var type: String? = "Prijava"
    var fields: [String: String]? = nil
    var updatedAt = Date()

    var kind: String {
        if let type, !type.isEmpty { return type }
        if password.isEmpty && website.isEmpty && username.isEmpty && !notes.isEmpty { return "Bilješka" }
        return "Prijava"
    }

    var extraFields: [String: String] { fields ?? [:] }
}

enum KeyraError: Error {
    case invalidData
    case keyUnavailable
    case invalidBackup
}

enum PasswordTools {
    static let currentIterations = 600_000

    static func derive(
        _ password: String,
        salt: Data,
        iterations: Int = currentIterations,
        keyLength: Int = 32
    ) throws -> Data {
        guard keyLength > 0, (100_000...2_000_000).contains(iterations) else {
            throw KeyraError.invalidData
        }

        let passwordBytes = Array(password.utf8)
        var output = [UInt8](repeating: 0, count: keyLength)
        let status = passwordBytes.withUnsafeBytes { passwordBuffer in
            salt.withUnsafeBytes { saltBuffer in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBuffer.bindMemory(to: Int8.self).baseAddress,
                    passwordBytes.count,
                    saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                    salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    &output,
                    keyLength
                )
            }
        }
        guard status == kCCSuccess else {
            throw KeyraError.keyUnavailable
        }
        return Data(output)
    }

    static func generate(length: Int, upper: Bool, lower: Bool, numbers: Bool, symbols: Bool) -> String {
        let selectedSets = [
            upper ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "",
            lower ? "abcdefghijklmnopqrstuvwxyz" : "",
            numbers ? "0123456789" : "",
            symbols ? "!@#$%&*+-_=.?" : ""
        ].filter { !$0.isEmpty }

        let sets = selectedSets.isEmpty ? ["abcdefghijklmnopqrstuvwxyz"] : selectedSets
        let pool = Array(sets.joined())
        var rng = SystemRandomNumberGenerator()
        var result = sets.compactMap { Array($0).randomElement(using: &rng) }
        while result.count < length {
            if let next = pool.randomElement(using: &rng) { result.append(next) }
        }
        result.shuffle(using: &rng)
        return String(result.prefix(length))
    }
}

func isStrongPassword(_ password: String) -> Bool {
    guard password.count >= 14 else { return false }
    let hasUpper = password.contains { $0.isUppercase }
    let hasLower = password.contains { $0.isLowercase }
    let hasDigit = password.contains { $0.isNumber }
    let hasSymbol = password.contains { !$0.isLetter && !$0.isNumber }
    guard [hasUpper, hasLower, hasDigit, hasSymbol].filter({ $0 }).count >= 3 else { return false }

    // Offline heuristic, not a breached-password database lookup.
    let normalized = password.lowercased()
    let predictableFragments = [
        "password", "passw0rd", "qwerty", "asdfgh",
        "123456", "654321", "letmein", "welcome", "lozinka", "zaporka"
    ]
    guard !predictableFragments.contains(where: { normalized.contains($0) }) else { return false }
    let chars = Array(normalized)
    if chars.count >= 5 {
        for index in 0...(chars.count - 5) {
            if (1..<5).allSatisfy({ chars[index + $0] == chars[index] }) { return false }
        }
    }
    return true
}

enum KeychainVault {
    private static let service = "com.keyra.app.vault"
    private static let account = "encryption-key"

    private static func existingKeyData() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var output: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &output) == errSecSuccess else {
            return nil
        }
        return output as? Data
    }

    static func rawKeyData() throws -> Data {
        if let existing = existingKeyData() {
            guard existing.count == 32 else { throw KeyraError.keyUnavailable }
            return existing
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        defer { for index in bytes.indices { bytes[index] = 0 } }
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw KeyraError.keyUnavailable
        }
        let data = Data(bytes)
        try replaceKeyData(data, allowInsert: true)
        return data
    }

    static func key() throws -> SymmetricKey {
        SymmetricKey(data: try rawKeyData())
    }

    static func replaceKeyData(_ data: Data, allowInsert: Bool = true) throws {
        guard data.count == 32 else { throw KeyraError.invalidData }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound, allowInsert else {
            throw KeyraError.keyUnavailable
        }

        var add = query
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        add[kSecValueData as String] = data
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeyraError.keyUnavailable
        }
    }

    static func clear() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

enum AuthVerifierKeychain {
    private static let service = "com.keyra.app.auth"
    private static let account = "master-verifier-v1"

    static func read() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var output: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &output) == errSecSuccess else {
            return nil
        }
        return output as? Data
    }

    static func write(_ data: Data) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
        let update: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw KeyraError.keyUnavailable }

        var add = query
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else {
            throw KeyraError.keyUnavailable
        }
    }

    static func clear() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

final class AuthStore {
    private let defaults = UserDefaults.standard
    private let legacyIterations = 120_000

    private struct Verifier: Codable {
        let version: Int
        let salt: Data
        let hash: Data
        let iterations: Int
    }

    var isSetup: Bool {
        AuthVerifierKeychain.read() != nil ||
            (defaults.data(forKey: "master_hash") != nil && defaults.data(forKey: "master_salt") != nil)
    }

    func create(password: String) -> Bool {
        var salt = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            return false
        }
        defer { salt.indices.forEach { salt[$0] = 0 } }

        do {
            let saltData = Data(salt)
            let hash = try PasswordTools.derive(password, salt: saltData)
            let verifier = Verifier(
                version: 1,
                salt: saltData,
                hash: hash,
                iterations: PasswordTools.currentIterations
            )
            let encoded = try PropertyListEncoder().encode(verifier)
            try AuthVerifierKeychain.write(encoded)
            clearLegacyDefaults()
            return true
        } catch {
            return false
        }
    }

    @discardableResult
    func clear() -> Bool {
        let verifierCleared = AuthVerifierKeychain.clear()
        clearLegacyDefaults()
        return verifierCleared
    }

    func verify(password: String) -> Bool {
        if let encoded = AuthVerifierKeychain.read() {
            guard
                let verifier = try? PropertyListDecoder().decode(Verifier.self, from: encoded),
                verifier.version == 1,
                verifier.salt.count == 16,
                verifier.hash.count == 32,
                (100_000...2_000_000).contains(verifier.iterations),
                let actual = try? PasswordTools.derive(
                    password,
                    salt: verifier.salt,
                    iterations: verifier.iterations
                )
            else {
                return false
            }

            let ok = constantTimeEqual(actual, verifier.hash)
            if ok && verifier.iterations < PasswordTools.currentIterations {
                return create(password: password)
            }
            return ok
        }

        // 0.6.x i stariji verifier: seli se u ThisDeviceOnly Keychain tek nakon točne lozinke.
        guard
            let salt = defaults.data(forKey: "master_salt"),
            let expected = defaults.data(forKey: "master_hash")
        else { return false }

        let storedIterations = defaults.integer(forKey: "master_iterations")
        let iterations = (100_000...2_000_000).contains(storedIterations)
            ? storedIterations
            : legacyIterations

        guard let actual = try? PasswordTools.derive(password, salt: salt, iterations: iterations) else {
            return false
        }

        let ok = constantTimeEqual(actual, expected)
        if ok {
            return create(password: password)
        }
        return false
    }

    private func clearLegacyDefaults() {
        defaults.removeObject(forKey: "master_hash")
        defaults.removeObject(forKey: "master_salt")
        defaults.removeObject(forKey: "master_iterations")
    }

    private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices {
            difference |= lhs[index] ^ rhs[index]
        }
        return difference == 0
    }
}

final class EncryptedVault {
    private let defaults = UserDefaults.standard
    private let legacyKey = "vault_blob"

    private func storageURL() throws -> URL {
        guard let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw KeyraError.keyUnavailable
        }

        var directory = root.appendingPathComponent("Keyra", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete]
        )
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? directory.setResourceValues(values)
        return directory.appendingPathComponent("vault.bin", isDirectory: false)
    }

    func save(_ items: [VaultItem]) throws {
        let data = try JSONEncoder().encode(items)
        let sealed = try AES.GCM.seal(data, using: KeychainVault.key())
        guard let combined = sealed.combined else { throw KeyraError.invalidData }

        let url = try storageURL()
        try combined.write(to: url, options: [.atomic, .completeFileProtection])
        defaults.removeObject(forKey: legacyKey)
    }

    func load() throws -> [VaultItem] {
        let url = try storageURL()
        let data: Data
        let migratedFromDefaults: Bool

        if FileManager.default.fileExists(atPath: url.path) {
            data = try Data(contentsOf: url)
            migratedFromDefaults = false
        } else if let legacy = defaults.data(forKey: legacyKey) {
            data = legacy
            migratedFromDefaults = true
        } else {
            return []
        }

        let box = try AES.GCM.SealedBox(combined: data)
        let clear = try AES.GCM.open(box, using: KeychainVault.key())
        let decoded = try JSONDecoder().decode([VaultItem].self, from: clear)

        if migratedFromDefaults {
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            defaults.removeObject(forKey: legacyKey)
        }
        return decoded
    }

    func recoveryKeyData() throws -> Data {
        try KeychainVault.rawKeyData()
    }

    func installRecoveryKey(_ data: Data) throws -> [VaultItem] {
        guard data.count == 32 else { throw KeyraError.invalidData }

        let url = try storageURL()
        let encrypted: Data?
        if FileManager.default.fileExists(atPath: url.path) {
            encrypted = try Data(contentsOf: url)
        } else {
            encrypted = defaults.data(forKey: legacyKey)
        }

        let verified: [VaultItem]
        if let encrypted {
            let box = try AES.GCM.SealedBox(combined: encrypted)
            let clear = try AES.GCM.open(box, using: SymmetricKey(data: data))
            verified = try JSONDecoder().decode([VaultItem].self, from: clear)
        } else {
            verified = []
        }

        try KeychainVault.replaceKeyData(data)
        return verified
    }

    func clear() {
        if let url = try? storageURL(), FileManager.default.fileExists(atPath: url.path) {
            try? FileManager.default.removeItem(at: url)
        }
        defaults.removeObject(forKey: legacyKey)
    }
}

enum PortableBackup {
    private static let maxPayloadBytes = 2_500_000
    private static let maxVaultItems = 10_000
    private static let saltBytes = 16
    private static let nonceBytes = 12
    private static let tagBytes = 16
    private static let legacyIOSIterations = 120_000
    private static let legacyAndroidIterations = 180_000

    private struct PortableVaultItem: Codable {
        let id: String
        let title: String
        let username: String
        let password: String
        let website: String
        let notes: String
        let category: String
        let favorite: Bool
        let type: String
        let fields: [String: String]
        let updatedAt: Int64

        init(_ item: VaultItem) {
            id = item.id.uuidString
            title = item.title
            username = item.username
            password = item.password
            website = item.website
            notes = item.notes
            category = item.category
            favorite = item.favorite
            type = item.kind
            fields = item.extraFields
            updatedAt = Int64((item.updatedAt.timeIntervalSince1970 * 1000.0).rounded())
        }

        func vaultItem() -> VaultItem {
            VaultItem(
                id: UUID(uuidString: id) ?? UUID(),
                title: title,
                username: username,
                password: password,
                website: website,
                notes: notes,
                category: category,
                favorite: favorite,
                type: type,
                fields: fields,
                updatedAt: Date(timeIntervalSince1970: Double(updatedAt) / 1000.0)
            )
        }
    }

    static func encrypt(_ items: [VaultItem], password: String) throws -> String {
        var salt = [UInt8](repeating: 0, count: saltBytes)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            throw KeyraError.keyUnavailable
        }
        let saltData = Data(salt)
        let key = SymmetricKey(data: try PasswordTools.derive(password, salt: saltData))
        let portableItems = items.map(PortableVaultItem.init)
        let clear = try JSONEncoder().encode(portableItems)
        let sealed = try AES.GCM.seal(clear, using: key)
        guard let combined = sealed.combined else { throw KeyraError.invalidBackup }

        // Shared KEYRA2 format on iOS and Android:
        // version.iterations.salt.(12-byte nonce + ciphertext + 16-byte GCM tag)
        return [
            "KEYRA2",
            String(PasswordTools.currentIterations),
            saltData.base64EncodedString(),
            combined.base64EncodedString()
        ].joined(separator: ".")
    }

    static func decrypt(_ text: String, password: String) throws -> [VaultItem] {
        guard text.utf8.count <= maxPayloadBytes else {
            throw KeyraError.invalidBackup
        }
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)

        if
            parts.count == 4,
            parts[0] == "KEYRA2",
            let iterations = Int(parts[1]),
            (100_000...2_000_000).contains(iterations),
            let salt = decodeSalt(parts[2]),
            let combined = Data(base64Encoded: String(parts[3]))
        {
            return try decryptCombined(
                combined,
                password: password,
                salt: salt,
                iterations: [iterations]
            )
        }

        // Legacy Android KEYRA2 stored nonce and ciphertext/tag separately.
        if
            parts.count == 5,
            parts[0] == "KEYRA2",
            let iterations = Int(parts[1]),
            (100_000...2_000_000).contains(iterations),
            let salt = decodeSalt(parts[2]),
            let combined = combineLegacyParts(noncePart: parts[3], payloadPart: parts[4])
        {
            return try decryptCombined(
                combined,
                password: password,
                salt: salt,
                iterations: [iterations]
            )
        }

        // Legacy iOS KEYRA1 used CryptoKit combined data and 120k iterations.
        if
            parts.count == 3,
            parts[0] == "KEYRA1",
            let salt = decodeSalt(parts[1]),
            let combined = Data(base64Encoded: String(parts[2]))
        {
            return try decryptCombined(
                combined,
                password: password,
                salt: salt,
                iterations: [legacyIOSIterations, legacyAndroidIterations]
            )
        }

        // Legacy Android KEYRA1 stored nonce and ciphertext/tag separately.
        if
            parts.count == 4,
            parts[0] == "KEYRA1",
            let salt = decodeSalt(parts[1]),
            let combined = combineLegacyParts(noncePart: parts[2], payloadPart: parts[3])
        {
            return try decryptCombined(
                combined,
                password: password,
                salt: salt,
                iterations: [legacyAndroidIterations, legacyIOSIterations]
            )
        }

        throw KeyraError.invalidBackup
    }

    private static func decodeSalt(_ value: Substring) -> Data? {
        guard
            let salt = Data(base64Encoded: String(value)),
            salt.count == saltBytes
        else {
            return nil
        }
        return salt
    }

    private static func combineLegacyParts(
        noncePart: Substring,
        payloadPart: Substring
    ) -> Data? {
        guard
            let nonce = Data(base64Encoded: String(noncePart)),
            nonce.count == nonceBytes,
            let payload = Data(base64Encoded: String(payloadPart)),
            payload.count >= tagBytes
        else {
            return nil
        }
        var combined = Data()
        combined.append(nonce)
        combined.append(payload)
        return combined
    }

    private static func decryptCombined(
        _ combined: Data,
        password: String,
        salt: Data,
        iterations: [Int]
    ) throws -> [VaultItem] {
        guard
            salt.count == saltBytes,
            combined.count >= nonceBytes + tagBytes
        else {
            throw KeyraError.invalidBackup
        }

        var lastError: Error?
        for iterationCount in iterations {
            do {
                let key = SymmetricKey(
                    data: try PasswordTools.derive(
                        password,
                        salt: salt,
                        iterations: iterationCount
                    )
                )
                let box = try AES.GCM.SealedBox(combined: combined)
                let clear = try AES.GCM.open(box, using: key)

                let decoded: [VaultItem]
                if let portable = try? JSONDecoder().decode([PortableVaultItem].self, from: clear) {
                    decoded = portable.map { $0.vaultItem() }
                } else {
                    // Backward compatibility with legacy iOS backups that encoded VaultItem directly.
                    decoded = try JSONDecoder().decode([VaultItem].self, from: clear)
                }

                guard decoded.count <= maxVaultItems else {
                    throw KeyraError.invalidBackup
                }
                guard Set(decoded.map(\.id)).count == decoded.count else {
                    throw KeyraError.invalidBackup
                }
                return decoded
            } catch {
                lastError = error
            }
        }

        if let lastError = lastError {
            throw lastError
        }
        throw KeyraError.invalidBackup
    }
}


func isStrongRecoveryPassphrase(_ passphrase: String) -> Bool {
    guard passphrase.count >= 16 else { return false }
    let classes = [
        passphrase.contains(where: { $0.isUppercase }),
        passphrase.contains(where: { $0.isLowercase }),
        passphrase.contains(where: { $0.isNumber }),
        passphrase.contains(where: { !$0.isLetter && !$0.isNumber && !$0.isWhitespace })
    ].filter { $0 }.count
    let words = passphrase
        .split(whereSeparator: { $0.isWhitespace })
        .filter { $0.count >= 3 }
    return classes >= 3 || words.count >= 4
}

enum RecoveryKeyEnvelope {
    private static let version = "KEYRAREC1"
    private static let iterations = 600_000
    private static let saltBytes = 16
    private static let rawKeyBytes = 32
    private static let maxPayloadBytes = 16_384

    static func encrypt(_ rawKey: Data, passphrase: String) throws -> String {
        guard rawKey.count == rawKeyBytes, isStrongRecoveryPassphrase(passphrase) else {
            throw KeyraError.invalidData
        }

        var salt = [UInt8](repeating: 0, count: saltBytes)
        defer { for index in salt.indices { salt[index] = 0 } }
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            throw KeyraError.keyUnavailable
        }

        let saltData = Data(salt)
        let derived = try PasswordTools.derive(
            passphrase,
            salt: saltData,
            iterations: iterations,
            keyLength: rawKeyBytes
        )
        let sealed = try AES.GCM.seal(rawKey, using: SymmetricKey(data: derived))
        guard let combined = sealed.combined else {
            throw KeyraError.invalidBackup
        }

        return [
            version,
            String(iterations),
            saltData.base64EncodedString(),
            combined.base64EncodedString()
        ].joined(separator: ".")
    }

    static func decrypt(_ payload: String, passphrase: String) throws -> Data {
        guard payload.utf8.count <= maxPayloadBytes else {
            throw KeyraError.invalidBackup
        }
        let parts = payload.trimmingCharacters(in: .whitespacesAndNewlines)
            .split(separator: ".", omittingEmptySubsequences: false)
        guard
            parts.count == 4,
            String(parts[0]) == version,
            let rounds = Int(parts[1]),
            (100_000...2_000_000).contains(rounds),
            let salt = Data(base64Encoded: String(parts[2])),
            salt.count == saltBytes,
            let combined = Data(base64Encoded: String(parts[3])),
            combined.count >= 12 + 16 + rawKeyBytes
        else {
            throw KeyraError.invalidBackup
        }

        let derived = try PasswordTools.derive(
            passphrase,
            salt: salt,
            iterations: rounds,
            keyLength: rawKeyBytes
        )
        let clear = try AES.GCM.open(
            AES.GCM.SealedBox(combined: combined),
            using: SymmetricKey(data: derived)
        )
        guard clear.count == rawKeyBytes else {
            throw KeyraError.invalidBackup
        }
        return clear
    }
}

struct KeyraBackupDocument: FileDocument {
    static var readableContentTypes: [UTType] {
        [UTType(filenameExtension: "keyra") ?? .data, .data, .plainText]
    }

    var payload: String

    init(payload: String = "") {
        self.payload = payload
    }

    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents else {
            throw KeyraError.invalidBackup
        }
        guard data.count <= 2_500_000 else {
            throw KeyraError.invalidBackup
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw KeyraError.invalidBackup
        }
        payload = text
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        let data = Data(payload.utf8)
        guard data.count <= 2_500_000 else {
            throw KeyraError.invalidBackup
        }
        return FileWrapper(regularFileWithContents: data)
    }
}

func cardExpiryNeedsAttention(_ expiry: String, now: Date = Date()) -> Bool {
    !expiry.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        !isCardExpiryNotPast(expiry, now: now)
}

func expiredCardIssueIDs(_ items: [VaultItem], now: Date = Date()) -> Set<UUID> {
    Set(items.filter {
        $0.kind == "Kartica" && cardExpiryNeedsAttention($0.extraFields["Vrijedi do"] ?? "", now: now)
    }.map(\.id))
}

func securityIssueIDs(_ items: [VaultItem]) -> Set<UUID> {
    let passwordItems = items.filter { $0.kind == "Prijava" || $0.kind == "Wi-Fi" }
    let duplicateIDs = Set(
        Dictionary(grouping: passwordItems.filter { !$0.password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }, by: { $0.password })
            .values
            .filter { $0.count > 1 }
            .flatMap { $0.map(\.id) }
    )
    let weakIDs = Set(passwordItems.filter { !isStrongPassword($0.password) }.map(\.id))
    let invalidTotpIDs = Set(items.filter {
        $0.kind == "Autentifikator" && totpConfigFromFields($0.extraFields) == nil
    }.map(\.id))
    return duplicateIDs.union(weakIDs).union(invalidTotpIDs).union(expiredCardIssueIDs(items))
}

func securityIssueCount(_ items: [VaultItem]) -> Int {
    securityIssueIDs(items).count
}

func resolvedCategoryName(_ selected: String, original: String?, existing: [String] = []) -> String? {
    if (original != nil && selected == original) || existing.contains(selected) { return selected }
    let trimmed = selected.trimmingCharacters(in: .whitespacesAndNewlines)
    let normalized = String(trimmed.prefix(40))
    return normalized.isEmpty ? nil : normalized
}

func securityScore(_ items: [VaultItem]) -> Int? {
    let passwordItems = items.filter { $0.kind == "Prijava" || $0.kind == "Wi-Fi" }
    guard !passwordItems.isEmpty else { return nil }
    let issueIDs = securityIssueIDs(items)
    return passwordItems.filter { !issueIDs.contains($0.id) }.count * 100 / passwordItems.count
}

func deviceAuthenticationAvailable() -> Bool {
    let context = LAContext()
    var error: NSError?
    return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
}

final class KeyraStore: ObservableObject {
    private let auth = AuthStore()
    private let vault = EncryptedVault()
    private let defaults = UserDefaults.standard

    @Published var items: [VaultItem] = []
    @Published var screen: KeyraScreen
    @Published var selected: VaultItem?
    @Published var message: String?
    @Published var vaultCategoryFilter: String?
    @Published var vaultTypeFilter: String?
    @Published var biometricEnabled: Bool
    @Published var sensitiveReauthEnabled: Bool
    @Published var autoLockSeconds: Int
    @Published var isSetup: Bool
    @Published var importingNewVault = false
    @Published private(set) var isCreatingVault = false
    @Published private(set) var isUnlockingVault = false
    @Published private(set) var isImportingVault = false
    @Published private(set) var isRecoveringVault = false

    private var sessionPassword: String?
    private var authenticationEpoch: UInt64 = 0
    private var appInForeground = true

    func appMovedToBackground() {
        appInForeground = false
        authenticationEpoch &+= 1
    }

    func appBecameActive() {
        appInForeground = true
    }

    private func canFinishAuthentication(_ epoch: UInt64) -> Bool {
        appInForeground && epoch == authenticationEpoch
    }

    init() {
        let setup = auth.isSetup
        self.isSetup = setup
        self.screen = setup ? .unlock : .onboarding
        self.vaultCategoryFilter = nil
        self.vaultTypeFilter = nil
        let authenticationAvailable = deviceAuthenticationAvailable()
        let savedBiometric = defaults.object(forKey: "biometric_enabled") as? Bool ?? true
        let savedSensitiveReauth = defaults.object(forKey: "sensitive_reauth_enabled") as? Bool ?? true
        self.biometricEnabled = savedBiometric && authenticationAvailable
        self.sensitiveReauthEnabled = savedSensitiveReauth && savedBiometric && authenticationAvailable
        self.autoLockSeconds = defaults.object(forKey: "auto_lock_seconds") as? Int ?? 0
    }

    func startCreate() {
        importingNewVault = false
        screen = .unlock
    }

    func startImport() {
        importingNewVault = true
        screen = .unlock
    }

    func startRecovery() {
        importingNewVault = false
        screen = .recovery
    }

    func cancelSetup() {
        guard !isCreatingVault, !isImportingVault, !isUnlockingVault, !isRecoveringVault else { return }
        importingNewVault = false
        if !isSetup { screen = .onboarding }
    }

    func open(_ target: KeyraScreen) {
        if target == .vault {
            vaultCategoryFilter = nil
            vaultTypeFilter = nil
        }
        screen = target
    }

    func openCategory(_ category: String, type: String) {
        vaultCategoryFilter = category
        vaultTypeFilter = type
        screen = .vault
    }

    func clearVaultCategoryFilter() {
        vaultCategoryFilter = nil
    }

    func addNew() { selected = nil; screen = .add }
    func editSelected() { if selected != nil { screen = .add } }
    func select(_ item: VaultItem) { selected = item; screen = .detail }

    func createVault(password: String) {
        guard !isSetup, !isCreatingVault, !isRecoveringVault else { return }
        guard (12...256).contains(password.count) else {
            message = "Glavna lozinka mora imati između 12 i 256 znakova."
            return
        }

        let requestEpoch = authenticationEpoch
        isCreatingVault = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let saved: Bool
            do {
                try self.vault.save([])
                saved = self.auth.create(password: password)
            } catch {
                saved = false
            }
            if !saved {
                self.vault.clear()
            }
            DispatchQueue.main.async {
                self.isCreatingVault = false
                if saved {
                    self.finishInitialSetup(
                        password: password, initialItems: [],
                        allowUnlock: self.canFinishAuthentication(requestEpoch)
                    )
                } else {
                    self.message = "Trezor nije moguće izraditi. Provjerite zaključavanje uređaja i pokušajte ponovno."
                }
            }
        }
    }

    func importNewVault(payload: String, password: String) {
        guard !isSetup, !isCreatingVault, !isImportingVault, !isRecoveringVault else { return }
        guard password.count >= 12 else {
            message = "Lozinka mora imati najmanje 12 znakova."
            return
        }
        guard !payload.isEmpty else {
            message = "Odaberite .keyra sigurnosnu kopiju."
            return
        }
        guard payload.utf8.count <= 2_500_000 else {
            message = "Sigurnosna kopija je prevelika."
            return
        }

        let requestEpoch = authenticationEpoch
        isImportingVault = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let imported: [VaultItem]?
            do {
                let decoded = try PortableBackup.decrypt(payload, password: password)
                try self.vault.save(decoded)
                if self.auth.create(password: password) {
                    imported = decoded
                } else {
                    self.vault.clear()
                    imported = nil
                }
            } catch {
                imported = nil
            }
            DispatchQueue.main.async {
                self.isImportingVault = false
                if let imported {
                    self.finishInitialSetup(
                        password: password, initialItems: imported,
                        allowUnlock: self.canFinishAuthentication(requestEpoch)
                    )
                    self.message = "Keyra trezor uspješno je uvezen."
                } else {
                    self.message = "Uvoz nije uspio. Provjerite kopiju, lozinku i raspoloživi prostor."
                }
            }
        }
    }

    func recoverInitialVault(
        recoveryPayload: String,
        recoveryPassphrase: String,
        backupPayload: String,
        backupPassword: String,
        newPassword: String
    ) {
        guard !isSetup, !isRecoveringVault, !isCreatingVault, !isImportingVault else { return }
        guard (12...256).contains(newPassword.count) else {
            message = "Nova glavna lozinka mora imati između 12 i 256 znakova."
            return
        }
        guard !recoveryPayload.isEmpty, recoveryPayload.utf8.count <= 16_384,
              !backupPayload.isEmpty, backupPayload.utf8.count <= 2_500_000,
              !recoveryPassphrase.isEmpty, !backupPassword.isEmpty else {
            message = "Odaberite valjani Recovery Key i sigurnosnu kopiju te unesite obje lozinke."
            return
        }

        let requestEpoch = authenticationEpoch
        isRecoveringVault = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let outcome: ([VaultItem]?, String)
            do {
                var rawKey = try RecoveryKeyEnvelope.decrypt(recoveryPayload, passphrase: recoveryPassphrase)
                defer { rawKey.resetBytes(in: 0..<rawKey.count) }
                let imported: [VaultItem]
                do {
                    imported = try PortableBackup.decrypt(backupPayload, password: backupPassword)
                } catch {
                    throw KeyraDocumentError.invalidOrOversized
                }

                do {
                    guard self.auth.clear() else { throw KeyraDocumentError.invalidOrOversized }
                    self.vault.clear()
                    guard KeychainVault.clear() else { throw KeyraDocumentError.invalidOrOversized }
                    _ = try self.vault.installRecoveryKey(rawKey)
                    try self.vault.save(imported)
                    guard self.auth.create(password: newPassword) else {
                        throw KeyraDocumentError.invalidOrOversized
                    }
                    outcome = (imported, "")
                } catch {
                    self.vault.clear()
                    _ = KeychainVault.clear()
                    _ = self.auth.clear()
                    outcome = (nil, "Obnova nije dovršena. Provjerite zaštitu i slobodan prostor uređaja.")
                }
            } catch {
                outcome = (nil, "Recovery Key ili sigurnosna kopija nisu valjani, ili lozinka nije ispravna.")
            }
            DispatchQueue.main.async {
                self.isRecoveringVault = false
                if let imported = outcome.0 {
                    self.finishInitialSetup(
                        password: newPassword, initialItems: imported,
                        allowUnlock: self.canFinishAuthentication(requestEpoch)
                    )
                    self.message = "Trezor je uspješno obnovljen."
                } else {
                    self.message = outcome.1
                }
            }
        }
    }

    private func finishInitialSetup(password: String, initialItems: [VaultItem], allowUnlock: Bool = true) {
        defaults.removeObject(forKey: "unlock_failed_attempts")
        defaults.removeObject(forKey: "unlock_lockout_until")
        isSetup = true
        importingNewVault = false
        guard allowUnlock && appInForeground else {
            lock()
            return
        }
        sessionPassword = password
        items = initialItems
        selected = nil
        screen = .vault
    }

    func unlock(password: String) {
        guard !isUnlockingVault, !isCreatingVault, !isRecoveringVault else { return }
        let now = Date().timeIntervalSince1970
        let lockoutUntil = defaults.double(forKey: "unlock_lockout_until")
        if lockoutUntil > now {
            let seconds = max(1, Int(ceil(lockoutUntil - now)))
            message = "Previše neuspjelih pokušaja. Pokušajte ponovno za \(seconds) s."
            return
        }
        let requestEpoch = authenticationEpoch
        isUnlockingVault = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            let verified = self.auth.verify(password: password)
            DispatchQueue.main.async {
                self.isUnlockingVault = false
                guard self.canFinishAuthentication(requestEpoch), self.screen == .unlock, self.isSetup else {
                    return
                }
                if !verified {
                    let attempts = self.defaults.integer(forKey: "unlock_failed_attempts") + 1
                    let penalty: TimeInterval
                    switch attempts {
                    case 10...: penalty = 300
                    case 7...: penalty = 60
                    case 5...: penalty = 30
                    default: penalty = 0
                    }
                    self.defaults.set(attempts, forKey: "unlock_failed_attempts")
                    self.defaults.set(penalty > 0 ? now + penalty : 0, forKey: "unlock_lockout_until")
                    self.message = penalty > 0
                        ? "Previše neuspjelih pokušaja. Trezor je privremeno zaključan."
                        : "Glavna lozinka nije ispravna."
                    return
                }

                self.defaults.removeObject(forKey: "unlock_failed_attempts")
                self.defaults.removeObject(forKey: "unlock_lockout_until")
                self.sessionPassword = password
                guard self.load() else {
                    self.sessionPassword = nil
                    return
                }
                self.screen = .vault
            }
        }
    }

    func unlockBiometric() {
        let requestEpoch = authenticationEpoch
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            message = "Biometrijsko otključavanje nije dostupno."
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Otključajte svoj Keyra trezor.") { success, error in
            DispatchQueue.main.async {
                guard self.canFinishAuthentication(requestEpoch), self.screen == .unlock else { return }
                if success {
                    if self.load() {
                        self.screen = .vault
                    }
                } else if let error {
                    self.message = error.localizedDescription
                }
            }
        }
    }

    func lock() {
        authenticationEpoch &+= 1
        items = []
        selected = nil
        sessionPassword = nil
        vaultCategoryFilter = nil
        vaultTypeFilter = nil
        screen = .unlock
    }

    @discardableResult
    func eraseAllLocalData() -> Bool {
        authenticationEpoch &+= 1
        vault.clear()
        let verifierCleared = auth.clear()
        let keyCleared = KeychainVault.clear()

        let keys = [
            "biometric_enabled",
            "sensitive_reauth_enabled",
            "auto_lock_seconds",
            "unlock_failed_attempts",
            "unlock_lockout_until"
        ]
        keys.forEach { defaults.removeObject(forKey: $0) }

        guard keyCleared && verifierCleared else {
            message = "Brisanje nije potpuno uspjelo. Ponovite postupak."
            return false
        }

        items = []
        selected = nil
        sessionPassword = nil
        vaultCategoryFilter = nil
        vaultTypeFilter = nil
        isSetup = false
        importingNewVault = false
        biometricEnabled = false
        sensitiveReauthEnabled = false
        autoLockSeconds = 0
        screen = .onboarding
        message = "Podaci trezora i zaštitni ključevi su izbrisani."
        return true
    }

    func save(_ item: VaultItem) {
        var saved = item
        saved.updatedAt = Date()
        var next = items
        if let index = next.firstIndex(where: { $0.id == item.id }) {
            next[index] = saved
        } else {
            next.insert(saved, at: 0)
        }

        do {
            try vault.save(next)
            items = next
            selected = saved
            screen = .vault
        } catch {
            message = "Stavku nije moguće spremiti. Pokušajte ponovno."
        }
    }

    func toggleSelectedFavorite() {
        guard let selected else { return }
        var updated = selected
        updated.favorite.toggle()
        updated.updatedAt = Date()

        var next = items
        guard let index = next.firstIndex(where: { $0.id == selected.id }) else { return }
        next[index] = updated

        do {
            try vault.save(next)
            items = next
            self.selected = updated
            message = updated.favorite
                ? "Stavka je dodana u favorite."
                : "Stavka je uklonjena iz favorita."
        } catch {
            message = "Promjenu favorita nije moguće spremiti."
        }
    }

    func deleteSelected() {
        guard let selected else { return }
        let next = items.filter { $0.id != selected.id }
        do {
            try vault.save(next)
            items = next
            self.selected = nil
            screen = .vault
        } catch {
            message = "Stavku nije moguće izbrisati. Pokušajte ponovno."
        }
    }

    func toggleBiometric(_ enabled: Bool) {
        if enabled && !deviceAuthenticationAvailable() {
            biometricEnabled = false
            sensitiveReauthEnabled = false
            message = "Biometrija ili zaključavanje uređaja nisu dostupni. Najprije zaštitite uređaj."
            return
        }

        biometricEnabled = enabled
        if !enabled { sensitiveReauthEnabled = false }
        defaults.set(enabled, forKey: "biometric_enabled")
        defaults.set(sensitiveReauthEnabled, forKey: "sensitive_reauth_enabled")
    }

    func toggleSensitiveReauth(_ enabled: Bool) {
        sensitiveReauthEnabled = enabled && biometricEnabled
        defaults.set(sensitiveReauthEnabled, forKey: "sensitive_reauth_enabled")
    }

    // A device-owner prompt can finish after navigation, vault locking, or app
    // backgrounding. Never run a delayed secret-reveal, export or erase action
    // unless the same unlocked vault view and item are still active.
    private func canCompleteProtectedAction(
        _ epoch: UInt64,
        screen expectedScreen: KeyraScreen,
        selectedID expectedSelectedID: UUID?
    ) -> Bool {
        guard canFinishAuthentication(epoch), isSetup, screen == expectedScreen,
              selected?.id == expectedSelectedID else { return false }
        return screen != .unlock && screen != .onboarding && screen != .recovery
    }

    func authorizeSensitive(reason: String, completion: @escaping () -> Void) {
        let requestEpoch = authenticationEpoch
        let expectedScreen = screen
        let expectedSelectedID = selected?.id
        guard canCompleteProtectedAction(
            requestEpoch, screen: expectedScreen, selectedID: expectedSelectedID
        ) else { return }

        guard sensitiveReauthEnabled && biometricEnabled else {
            completion()
            return
        }

        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            message = "Potvrda identiteta nije dostupna na ovom uređaju."
            return
        }

        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, error in
            DispatchQueue.main.async { [weak self] in
                guard let self, self.canCompleteProtectedAction(
                    requestEpoch, screen: expectedScreen, selectedID: expectedSelectedID
                ) else { return }
                if success {
                    completion()
                } else if let error {
                    self.message = error.localizedDescription
                }
            }
        }
    }

    func authorizeCritical(reason: String, completion: @escaping () -> Void) {
        let requestEpoch = authenticationEpoch
        let expectedScreen = screen
        let expectedSelectedID = selected?.id
        guard canCompleteProtectedAction(
            requestEpoch, screen: expectedScreen, selectedID: expectedSelectedID
        ) else { return }

        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            // Devices without an owner-auth prompt still require an active unlocked session.
            completion()
            return
        }

        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [weak self] success, error in
            DispatchQueue.main.async { [weak self] in
                guard let self, self.canCompleteProtectedAction(
                    requestEpoch, screen: expectedScreen, selectedID: expectedSelectedID
                ) else { return }
                if success {
                    completion()
                } else if let error {
                    self.message = error.localizedDescription
                }
            }
        }
    }

    func cycleAutoLock() {
        switch autoLockSeconds {
        case 0: autoLockSeconds = 30
        case 30: autoLockSeconds = 60
        case 60: autoLockSeconds = 300
        default: autoLockSeconds = 0
        }
        defaults.set(autoLockSeconds, forKey: "auto_lock_seconds")
        message = "Automatsko zaključavanje: " + autoLockLabel
    }

    var autoLockLabel: String {
        switch autoLockSeconds {
        case 0: return "Odmah"
        case 30: return "30 sekundi"
        case 60: return "1 minuta"
        case 300: return "5 minuta"
        default: return "\(autoLockSeconds) s"
        }
    }

    func makeBackupPayload() -> String? {
        guard let password = sessionPassword else {
            message = "Za sigurnosnu kopiju prvo otključajte trezor glavnom lozinkom."
            return nil
        }
        do {
            return try PortableBackup.encrypt(items, password: password)
        } catch {
            message = "Sigurnosnu kopiju nije moguće izraditi."
            return nil
        }
    }

    func makeRecoveryKeyPayload(passphrase: String) -> String? {
        guard isStrongRecoveryPassphrase(passphrase) else {
            message = "Recovery lozinka mora imati najmanje 16 znakova i dovoljnu složenost ili najmanje četiri riječi."
            return nil
        }
        do {
            let rawKey = try vault.recoveryKeyData()
            return try RecoveryKeyEnvelope.encrypt(rawKey, passphrase: passphrase)
        } catch {
            message = "Recovery Key datoteku nije moguće izraditi."
            return nil
        }
    }

    @discardableResult
    func importRecoveryKeyPayload(_ payload: String, passphrase: String) -> Bool {
        guard !payload.isEmpty, payload.utf8.count <= 16_384 else {
            message = "Recovery Key datoteka nije valjana."
            return false
        }
        do {
            let rawKey = try RecoveryKeyEnvelope.decrypt(payload, passphrase: passphrase)
            let verifiedItems = try vault.installRecoveryKey(rawKey)
            if !verifiedItems.isEmpty {
                items = verifiedItems
            }
            message = verifiedItems.isEmpty
                ? "Recovery Key je obnovljen. Za povrat podataka odaberite zasebnu šifriranu sigurnosnu kopiju."
                : "Recovery Key je verificiran i ponovno zaštićen Keychainom ovog uređaja."
            return true
        } catch {
            message = "Recovery Key je oštećen, izmijenjen, ne odgovara ovom trezoru ili recovery lozinka nije ispravna."
            return false
        }
    }

    @discardableResult
    func importBackupPayload(_ text: String) -> Bool {
        guard let password = sessionPassword else {
            message = "Za uvoz prvo otključajte trezor glavnom lozinkom."
            return false
        }
        guard !text.isEmpty else {
            message = "Odabrana sigurnosna kopija je prazna."
            return false
        }
        guard text.utf8.count <= 2_500_000 else {
            message = "Sigurnosna kopija je prevelika za siguran uvoz."
            return false
        }

        do {
            let imported = try PortableBackup.decrypt(text, password: password)
            try vault.save(imported)
            items = imported
            selected = nil
            message = "Sigurnosna kopija uspješno je uvezena."
            return true
        } catch {
            message = "Sigurnosna kopija nije valjana, lozinka nije odgovarajuća ili spremanje nije uspjelo."
            return false
        }
    }

    @discardableResult
    private func load() -> Bool {
        do {
            items = try vault.load()
            return true
        } catch {
            message = "Trezor nije moguće otvoriti. Podaci nisu promijenjeni."
            return false
        }
    }

}

@main
struct KeyraApp: App {
    @StateObject private var store = KeyraStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(store)
                .preferredColorScheme(.dark)
        }
    }
}

struct RootView: View {
    @EnvironmentObject var store: KeyraStore
    @Environment(\.scenePhase) private var scenePhase
    @State private var splash = true
    @State private var backgroundedAt: Date?
    @State private var screenCaptured = UIScreen.main.isCaptured
    @State private var appPrivacyShield = false

    var body: some View {
        ZStack(alignment: .bottom) {
            LinearGradient(
                colors: [
                    midnight,
                    Color(hex: 0x07172A),
                    Color(hex: 0x091426),
                    midnight
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            if splash {
                SplashView()
            } else {
                switch store.screen {
                case .onboarding: OnboardingView().keyraPageWidth(680)
                case .recovery: RecoverySetupView().keyraPageWidth(680)
                case .unlock: UnlockView().keyraPageWidth(620)
                case .vault: VaultView().keyraPageWidth()
                case .collections: CollectionsView().keyraPageWidth()
                case .generator: GeneratorView().keyraPageWidth(760)
                case .add: AddEditView(store: store).keyraPageWidth(760)
                case .detail: DetailView().keyraPageWidth(760)
                case .settings: SettingsView().keyraPageWidth(760)
                case .security: SecurityCenterView().keyraPageWidth(760)
                }

                if [.vault, .collections, .generator, .settings, .security].contains(store.screen) {
                    BottomBar()
                }
            }

            if (scenePhase != .active || appPrivacyShield || screenCaptured) && !splash {
                ZStack {
                    midnight.ignoresSafeArea()
                    VStack(spacing: 14) {
                        KeyraMark(size: 88)
                        Text("Keyra").font(.largeTitle.bold()).foregroundStyle(.white)
                        Text(
                            screenCaptured
                                ? "Sadržaj je skriven dok je aktivno snimanje zaslona."
                                : "Trezor je zaključan radi vaše privatnosti."
                        )
                        .foregroundStyle(muted)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 24)
                    }
                }
                .transition(.opacity)
                .zIndex(50)
            }

            if let message = store.message {
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.white)
                    .padding()
                    .background(slate2)
                    .clipShape(RoundedRectangle(cornerRadius: 18))
                    .padding(.bottom, 86)
                    .padding(.horizontal)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .task(id: message) {
                        try? await Task.sleep(nanoseconds: 2_600_000_000)
                        withAnimation { store.message = nil }
                    }
            }
        }
        .task {
            try? await Task.sleep(nanoseconds: 850_000_000)
            withAnimation(.easeOut(duration: 0.3)) { splash = false }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
            screenCaptured = UIScreen.main.isCaptured
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.willResignActiveNotification)) { _ in
            appPrivacyShield = true
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in
            screenCaptured = UIScreen.main.isCaptured
            appPrivacyShield = false
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background {
                store.appMovedToBackground()
            } else if phase == .active {
                store.appBecameActive()
            }
            if phase == .background && store.isSetup && store.screen != .unlock {
                if store.autoLockSeconds == 0 {
                    store.lock()
                } else {
                    backgroundedAt = Date()
                }
            } else if phase == .active {
                if
                    let started = backgroundedAt,
                    store.autoLockSeconds > 0,
                    Date().timeIntervalSince(started) >= Double(store.autoLockSeconds)
                {
                    store.lock()
                }
                backgroundedAt = nil
            }
        }
    }
}

struct KeyraMark: View {
    var size: CGFloat = 74

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size / 4)
                .fill(midnight)

            Canvas { context, canvas in
                let w = canvas.width
                let h = canvas.height

                var left = Path()
                left.move(to: CGPoint(x: w * 0.20, y: h * 0.14))
                left.addLine(to: CGPoint(x: w * 0.43, y: h * 0.08))
                left.addLine(to: CGPoint(x: w * 0.43, y: h * 0.43))
                left.addLine(to: CGPoint(x: w * 0.68, y: h * 0.22))
                left.addLine(to: CGPoint(x: w * 0.84, y: h * 0.28))
                left.addLine(to: CGPoint(x: w * 0.55, y: h * 0.52))
                left.addLine(to: CGPoint(x: w * 0.84, y: h * 0.79))
                left.addLine(to: CGPoint(x: w * 0.65, y: h * 0.88))
                left.addLine(to: CGPoint(x: w * 0.43, y: h * 0.65))
                left.addLine(to: CGPoint(x: w * 0.43, y: h * 0.90))
                left.addLine(to: CGPoint(x: w * 0.20, y: h * 0.78))
                left.closeSubpath()

                context.fill(
                    left,
                    with: .linearGradient(
                        Gradient(colors: [cyan, Color(hex: 0x22BDF7), indigo]),
                        startPoint: CGPoint(x: 0, y: 0),
                        endPoint: CGPoint(x: w, y: h)
                    )
                )

                let keyholeCenter = CGPoint(x: w * 0.50, y: h * 0.50)
                let circle = Path(ellipseIn: CGRect(x: keyholeCenter.x - w * 0.07, y: keyholeCenter.y - h * 0.07, width: w * 0.14, height: h * 0.14))
                context.fill(circle, with: .color(midnight))
                var stem = Path()
                stem.move(to: CGPoint(x: w * 0.47, y: h * 0.55))
                stem.addLine(to: CGPoint(x: w * 0.53, y: h * 0.55))
                stem.addLine(to: CGPoint(x: w * 0.58, y: h * 0.73))
                stem.addLine(to: CGPoint(x: w * 0.42, y: h * 0.73))
                stem.closeSubpath()
                context.fill(stem, with: .color(midnight))
            }
            .padding(size * 0.08)
        }
        .overlay(RoundedRectangle(cornerRadius: size / 4).stroke(cyan.opacity(0.65), lineWidth: 1))
        .frame(width: size, height: size)
        .shadow(color: cyan.opacity(0.28), radius: 20)
    }
}

struct SplashView: View {
    var body: some View {
        GeometryReader { proxy in
            let compact = proxy.size.height < 620 || proxy.size.width < 340
            ZStack {
                LinearGradient(
                    colors: [midnight, Color(hex: 0x071B36), midnight],
                    startPoint: .top,
                    endPoint: .bottom
                )
                .ignoresSafeArea()

                VStack(spacing: compact ? 10 : 14) {
                    KeyraMark(size: compact ? 94 : 118)
                    Text("Keyra")
                        .font(.system(size: compact ? 46 : 54, weight: .black, design: .rounded))
                        .foregroundStyle(.white)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)
                    Text("SIGURNI UPRAVITELJ LOZINKI")
                        .font(.system(size: compact ? 10 : 11, weight: .medium))
                        .tracking(compact ? 1.8 : 2.4)
                        .foregroundStyle(muted)
                        .lineLimit(1)
                        .minimumScaleFactor(0.72)
                }
                .padding(.horizontal, 24)
            }
        }
    }
}

struct BrandHeader: View {
    @EnvironmentObject var store: KeyraStore
    let subtitle: String

    private var notificationCount: Int {
        securityIssueCount(store.items)
    }

    var body: some View {
        ViewThatFits(in: .horizontal) {
            header(compact: false)
            header(compact: true)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    @ViewBuilder
    private func header(compact: Bool) -> some View {
        HStack(spacing: compact ? 8 : 12) {
            KeyraMark(size: compact ? 42 : 50)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 8) {
                    Text("Keyra")
                        .font(.system(size: compact ? 27 : 31, weight: .black, design: .rounded))
                        .foregroundStyle(.white)
                        .lineLimit(1)


                }

                Text(subtitle.uppercased())
                    .font(.system(size: compact ? 9 : 10, weight: .semibold))
                    .tracking(compact ? 1.2 : 1.8)
                    .foregroundStyle(muted)
                    .lineLimit(1)
                    .minimumScaleFactor(0.72)
            }

            Spacer(minLength: 4)

            Button {
                store.open(.security)
            } label: {
                ZStack(alignment: .topTrailing) {
                    Image(systemName: "bell.fill")
                        .foregroundStyle(.white)
                        .frame(width: compact ? 36 : 40, height: compact ? 36 : 40)
                        .background(midnight.opacity(0.72))
                        .clipShape(Circle())

                    if notificationCount > 0 {
                        Text(notificationCount > 9 ? "9+" : "\(notificationCount)")
                            .font(.system(size: 8, weight: .bold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(danger)
                            .clipShape(Capsule())
                            .offset(x: 3, y: -3)
                    }
                }
            }
            .buttonStyle(.plain)
            .accessibilityLabel(
                notificationCount > 0
                    ? "Sigurnosna upozorenja: \(notificationCount)"
                    : "Nema sigurnosnih upozorenja"
            )

            Button {
                store.open(.settings)
            } label: {
                Image(systemName: "person.crop.circle")
                    .font(.system(size: compact ? 19 : 21))
                    .foregroundStyle(.white)
                    .frame(width: compact ? 36 : 40, height: compact ? 36 : 40)
                    .background(
                        LinearGradient(
                            colors: [cyan.opacity(0.18), indigo.opacity(0.20)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .overlay(Circle().stroke(cyan.opacity(0.62), lineWidth: 1))
                    .clipShape(Circle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Otvori postavke profila")
        }
        .padding(.horizontal, compact ? 12 : 16)
        .padding(.vertical, compact ? 9 : 11)
        .background(
            LinearGradient(
                colors: [slate2.opacity(0.98), Color(hex: 0x101B2F).opacity(0.98)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .overlay(
            RoundedRectangle(cornerRadius: 26)
                .stroke(
                    LinearGradient(
                        colors: [cyan.opacity(0.42), ice.opacity(0.16), indigo.opacity(0.28)],
                        startPoint: .leading,
                        endPoint: .trailing
                    ),
                    lineWidth: 1
                )
        )
        .clipShape(RoundedRectangle(cornerRadius: 26))
        .shadow(color: .black.opacity(0.22), radius: 10, y: 6)
    }
}

struct GlassCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) { content }
            .padding(.horizontal, 20)
            .padding(.vertical, 18)
            .background(
                LinearGradient(
                    colors: [slate2.opacity(0.98), slate.opacity(0.94)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .overlay(
                RoundedRectangle(cornerRadius: 26)
                    .stroke(
                        LinearGradient(
                            colors: [cyan.opacity(0.42), ice.opacity(0.14), indigo.opacity(0.28)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        ),
                        lineWidth: 1
                    )
            )
            .clipShape(RoundedRectangle(cornerRadius: 26))
            .shadow(color: .black.opacity(0.20), radius: 9, y: 5)
    }
}

struct OnboardingHeroBadge: View {
    let icon: String

    var body: some View {
        Image(systemName: icon)
            .font(.system(size: 22, weight: .semibold))
            .foregroundStyle(ice)
            .frame(width: 46, height: 46)
            .background(slate2.opacity(0.96))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(ice.opacity(0.38), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }
}

struct OnboardingVaultHero: View {
    let compact: Bool

    var body: some View {
        ZStack {
            RadialGradient(
                colors: [indigo.opacity(0.30), Color(hex: 0x0A3150).opacity(0.72), midnight],
                center: .center,
                startRadius: 6,
                endRadius: compact ? 130 : 170
            )

            RoundedRectangle(cornerRadius: compact ? 26 : 32)
                .fill(slate.opacity(0.92))
                .frame(width: compact ? 94 : 116, height: compact ? 94 : 116)
                .overlay(
                    RoundedRectangle(cornerRadius: compact ? 26 : 32)
                        .stroke(cyan.opacity(0.62), lineWidth: 1)
                )
                .overlay(KeyraMark(size: compact ? 72 : 90))

            VStack {
                HStack {
                    OnboardingHeroBadge(icon: "faceid")
                    Spacer()
                    OnboardingHeroBadge(icon: "shield")
                }
                Spacer()
                HStack {
                    OnboardingHeroBadge(icon: "creditcard")
                    Spacer()
                    OnboardingHeroBadge(icon: "icloud")
                }
            }
            .padding(compact ? 12 : 16)
        }
        .frame(height: compact ? 154 : 190)
        .clipShape(RoundedRectangle(cornerRadius: compact ? 24 : 30))
        .overlay(
            RoundedRectangle(cornerRadius: compact ? 24 : 30)
                .stroke(
                    LinearGradient(
                        colors: [cyan.opacity(0.72), indigo.opacity(0.58)],
                        startPoint: .leading,
                        endPoint: .trailing
                    ),
                    lineWidth: 1
                )
        )
    }
}

struct OnboardingView: View {
    @EnvironmentObject var store: KeyraStore

    var body: some View {
        GeometryReader { proxy in
            let compact = proxy.size.height < 800 || proxy.size.width < 360
            let short = proxy.size.height < 590

            VStack(spacing: 0) {
                VStack(spacing: compact ? 7 : 11) {
                        KeyraMark(size: short ? 50 : (compact ? 64 : 82))
                            .padding(.top, compact ? 6 : 14)

                        Text("Keyra")
                            .font(.system(size: compact ? 34 : 42, weight: .black, design: .rounded))
                            .foregroundStyle(.white)
                            .lineLimit(1)

                        Text("SIGURNI UPRAVITELJ LOZINKI")
                            .font(.system(size: compact ? 9 : 11))
                            .tracking(compact ? 1.4 : 2)
                            .foregroundStyle(muted)
                            .lineLimit(1)
                            .minimumScaleFactor(0.75)

                        if !short {
                            OnboardingVaultHero(compact: compact)
                                .padding(.top, compact ? 3 : 7)
                        }

                        VStack(alignment: .leading, spacing: compact ? 5 : 8) {
                            Text("Sigurniji način upravljanja lozinkama")
                                .font(.system(size: compact ? 25 : 31, weight: .black))
                                .foregroundStyle(.white)
                                .minimumScaleFactor(0.8)
                            Text("Čuvajte svoje lozinke i osjetljive podatke na jednom sigurnom mjestu.")
                                .font(compact ? .subheadline : .body)
                                .foregroundStyle(muted)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.top, compact ? 6 : 12)


                    }
                .padding(.horizontal, compact ? 16 : 22)
                .frame(maxHeight: .infinity)

                VStack(spacing: 8) {
                    Button {
                        store.startCreate()
                    } label: {
                        HStack {
                            Text("Izradi trezor").fontWeight(.bold)
                            Image(systemName: "arrow.right")
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: compact ? 50 : 56)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(midnight)
                    .background(cyan)
                    .clipShape(Capsule())

                    Button {
                        store.startImport()
                    } label: {
                        HStack {
                            Image(systemName: "square.and.arrow.down")
                            Text("Uvezi Keyra trezor").fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: compact ? 46 : 52)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.white)
                    .overlay(Capsule().stroke(cyan.opacity(0.72), lineWidth: 1))

                    Button {
                        store.startRecovery()
                    } label: {
                        HStack {
                            Image(systemName: "key.horizontal.fill")
                            Text("Imam Recovery Key").fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: compact ? 42 : 48)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(ice)
                }
                .padding(.horizontal, compact ? 16 : 22)
                .padding(.top, 8)
                .padding(.bottom, max(proxy.safeAreaInsets.bottom, 8))
            }
        }
    }
}

struct RecoverySetupView: View {
    @EnvironmentObject var store: KeyraStore
    @State private var recoveryPayload: String?
    @State private var backupPayload: String?
    @State private var recoveryPassphrase = ""
    @State private var backupPassword = ""
    @State private var newPassword = ""
    @State private var confirmPassword = ""
    @State private var reveal = false
    @State private var showRecoveryPicker = false
    @State private var showBackupPicker = false

    private var canRestore: Bool {
        recoveryPayload != nil &&
        backupPayload != nil &&
        !recoveryPassphrase.isEmpty &&
        !backupPassword.isEmpty &&
        newPassword.count >= 12 &&
        !confirmPassword.isEmpty
    }

    var body: some View {
        GeometryReader { proxy in
            let compact = proxy.size.height < 720 || proxy.size.width < 360

            ScrollView {
                VStack(spacing: compact ? 10 : 14) {
                    HStack {
                        Button {
                            store.cancelSetup()
                        } label: {
                            Image(systemName: "chevron.left")
                                .font(.headline)
                                .frame(width: 42, height: 42)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(ice)
                        Spacer()
                    }

                    KeyraMark(size: compact ? 58 : 72)
                    Text("Obnovite Keyra trezor")
                        .font(.system(size: compact ? 26 : 31, weight: .black))
                        .foregroundStyle(.white)
                        .multilineTextAlignment(.center)

                    Text("Za obnovu trezora trebaju vam Recovery Key i odgovarajuća sigurnosna kopija.")
                        .font(compact ? .footnote : .subheadline)
                        .foregroundStyle(muted)
                        .multilineTextAlignment(.center)
                        .padding(.bottom, 4)

                    VStack(alignment: .leading, spacing: 12) {
                        Text("1. Recovery Key")
                            .font(.headline)
                            .foregroundStyle(.white)

                        Button {
                            showRecoveryPicker = true
                        } label: {
                            HStack {
                                Image(systemName: "key.horizontal.fill")
                                Text(recoveryPayload == nil ? "Odaberi Keyra-Recovery.keyra" : "Recovery Key učitan")
                                Spacer()
                                Image(systemName: recoveryPayload == nil ? "chevron.right" : "checkmark.circle.fill")
                            }
                            .frame(maxWidth: .infinity)
                            .padding(14)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(recoveryPayload == nil ? .white : good)
                        .background(slate2)
                        .clipShape(RoundedRectangle(cornerRadius: 14))

                        SecureField("Recovery lozinka", text: $recoveryPassphrase)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .padding(14)
                            .background(slate2)
                            .clipShape(RoundedRectangle(cornerRadius: 14))

                        Divider().overlay(ice.opacity(0.18))

                        Text("2. KEYRA2 sigurnosna kopija")
                            .font(.headline)
                            .foregroundStyle(.white)

                        Button {
                            showBackupPicker = true
                        } label: {
                            HStack {
                                Image(systemName: "archivebox")
                                Text(backupPayload == nil ? "Odaberi .keyra sigurnosnu kopiju" : "KEYRA2 kopija učitana")
                                Spacer()
                                Image(systemName: backupPayload == nil ? "chevron.right" : "checkmark.circle.fill")
                            }
                            .frame(maxWidth: .infinity)
                            .padding(14)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(backupPayload == nil ? .white : good)
                        .background(slate2)
                        .clipShape(RoundedRectangle(cornerRadius: 14))

                        SecureField("Lozinka sigurnosne kopije", text: $backupPassword)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .padding(14)
                            .background(slate2)
                            .clipShape(RoundedRectangle(cornerRadius: 14))

                        Divider().overlay(ice.opacity(0.18))

                        Text("3. Nova glavna lozinka")
                            .font(.headline)
                            .foregroundStyle(.white)

                        Group {
                            if reveal {
                                TextField("Nova glavna lozinka", text: $newPassword)
                                TextField("Ponovite novu glavnu lozinku", text: $confirmPassword)
                            } else {
                                SecureField("Nova glavna lozinka", text: $newPassword)
                                SecureField("Ponovite novu glavnu lozinku", text: $confirmPassword)
                            }
                        }
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onChange(of: newPassword) { _, value in
                            if value.count > 256 { newPassword = String(value.prefix(256)) }
                        }
                        .onChange(of: confirmPassword) { _, value in
                            if value.count > 256 { confirmPassword = String(value.prefix(256)) }
                        }
                        .padding(14)
                        .background(slate2)
                        .clipShape(RoundedRectangle(cornerRadius: 14))

                        HStack {
                            Text("Najmanje 12 znakova.")
                                .font(.caption)
                                .foregroundStyle(muted)
                            Spacer()
                            Button(reveal ? "Sakrij lozinke" : "Prikaži lozinke") {
                                reveal.toggle()
                            }
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(ice)
                        }

                        Button {
                            guard newPassword == confirmPassword else {
                                store.message = "Nove glavne lozinke se ne podudaraju."
                                return
                            }
                            store.recoverInitialVault(
                                recoveryPayload: recoveryPayload ?? "",
                                recoveryPassphrase: recoveryPassphrase,
                                backupPayload: backupPayload ?? "",
                                backupPassword: backupPassword,
                                newPassword: newPassword
                            )
                        } label: {
                            HStack {
                                if store.isRecoveringVault {
                                    ProgressView().tint(midnight)
                                } else {
                                    Image(systemName: "arrow.clockwise.circle.fill")
                                }
                                Text(store.isRecoveringVault ? "Obnova trezora…" : "Obnovi trezor").fontWeight(.bold)
                            }
                            .frame(maxWidth: .infinity)
                            .frame(height: 54)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(midnight)
                        .background(canRestore ? cyan : cyan.opacity(0.35))
                        .clipShape(Capsule())
                        .disabled(!canRestore || store.isRecoveringVault)
                    }
                    .padding(compact ? 14 : 18)
                    .background(slate.opacity(0.96))
                    .clipShape(RoundedRectangle(cornerRadius: 22))
                    .overlay(RoundedRectangle(cornerRadius: 22).stroke(cyan.opacity(0.34), lineWidth: 1))

                    Text("Oba artefakta provjeravaju se prije spremanja. Recovery Key nije sigurnosna kopija podataka i ne šalje se na Keyra poslužitelje.")
                        .font(.caption)
                        .foregroundStyle(muted)
                        .multilineTextAlignment(.center)
                        .padding(.top, 2)
                }
                .padding(.horizontal, compact ? 16 : 22)
                .padding(.top, 8)
                .padding(.bottom, max(proxy.safeAreaInsets.bottom, 16))
            }
        }
        .fileImporter(
            isPresented: $showRecoveryPicker,
            allowedContentTypes: KeyraBackupDocument.readableContentTypes,
            allowsMultipleSelection: false
        ) { result in
            do {
                guard let url = try result.get().first else { return }
                let accessed = url.startAccessingSecurityScopedResource()
                defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                let text = try readLimitedKeyraText(url, maxBytes: 16_384)
                if text.isEmpty {
                    store.message = "Recovery Key datoteka nije valjana ili je prevelika."
                    recoveryPayload = nil
                    return
                }
                recoveryPayload = text
                store.message = "Recovery Key datoteka je učitana."
            } catch {
                recoveryPayload = nil
                store.message = "Recovery Key datoteku nije moguće otvoriti."
            }
        }
        .fileImporter(
            isPresented: $showBackupPicker,
            allowedContentTypes: KeyraBackupDocument.readableContentTypes,
            allowsMultipleSelection: false
        ) { result in
            do {
                guard let url = try result.get().first else { return }
                let accessed = url.startAccessingSecurityScopedResource()
                defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                let text = try readLimitedKeyraText(url, maxBytes: 2_500_000)
                if text.isEmpty {
                    store.message = "KEYRA2 sigurnosna kopija nije valjana ili je prevelika."
                    backupPayload = nil
                    return
                }
                backupPayload = text
                store.message = "KEYRA2 sigurnosna kopija je učitana."
            } catch {
                backupPayload = nil
                store.message = "KEYRA2 sigurnosnu kopiju nije moguće otvoriti."
            }
        }
    }
}

struct UnlockView: View {
    @EnvironmentObject var store: KeyraStore
    @State private var password = ""
    @State private var confirm = ""
    @State private var reveal = false
    @State private var importPayload: String?
    @State private var showImportPicker = false

    private var creating: Bool { !store.isSetup }
    private var importing: Bool { creating && store.importingNewVault }

    var body: some View {
        GeometryReader { proxy in
            let compact = proxy.size.height < 700 || proxy.size.width < 360
            ScrollView {
            VStack(spacing: compact ? 11 : 16) {
                KeyraMark(size: compact ? 66 : 84).padding(.top, compact ? 10 : 24)
                Text("Keyra")
                    .font(.system(size: compact ? 36 : 44, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                Text("SIGURNI UPRAVITELJ LOZINKI")
                    .font(.system(size: 12))
                    .tracking(2)
                    .foregroundStyle(muted)

                GlassCard {
                    Text(
                        importing
                            ? "Uvezite Keyra trezor"
                            : (creating ? "Izradite trezor" : "Otključajte trezor")
                    )
                    .font(.system(size: compact ? 26 : 31, weight: .black))
                    .foregroundStyle(.white)

                    Text(
                        importing
                            ? "Odaberite šifriranu .keyra datoteku i unesite lozinku sigurnosne kopije."
                            : (creating
                                ? "Postavite glavnu lozinku kojom ćete otključavati svoj trezor."
                                : "Unesite glavnu lozinku kako biste pristupili svom sigurnom trezoru.")
                    )
                    .foregroundStyle(muted)

                    SecretField(title: "Glavna lozinka", text: $password, reveal: $reveal)
                        .onChange(of: password) { _, value in
                            if creating && !importing && value.count > 256 {
                                password = String(value.prefix(256))
                            }
                        }
                    if creating && !importing {
                        SecretField(title: "Ponovite glavnu lozinku", text: $confirm, reveal: $reveal)
                            .onChange(of: confirm) { _, value in
                                if value.count > 256 { confirm = String(value.prefix(256)) }
                            }
                        Text("Glavna lozinka: najmanje 12 znakova.")
                            .font(.caption)
                            .foregroundStyle(muted)
                    }
                    if importing {
                        Button {
                            showImportPicker = true
                        } label: {
                            HStack {
                                Image(systemName: "folder")
                                Text(importPayload == nil ? "Odaberi .keyra datoteku" : "Sigurnosna kopija odabrana")
                                Spacer()
                                Image(systemName: importPayload == nil ? "chevron.right" : "checkmark.circle.fill")
                            }
                            .padding(14)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(importPayload == nil ? .white : good)
                        .background(slate2)
                        .clipShape(RoundedRectangle(cornerRadius: 14))
                        Text("Uvoz neće zamijeniti podatke ako provjera ili trajno spremanje ne uspiju.")
                            .font(.caption)
                            .foregroundStyle(muted)
                    }

                    Button {
                        if importing {
                            if let importPayload {
                                store.importNewVault(payload: importPayload, password: password)
                            }
                        } else if creating {
                            if password != confirm { store.message = "Lozinke se ne podudaraju." }
                            else { store.createVault(password: password) }
                        } else {
                            store.unlock(password: password)
                        }
                    } label: {
                        HStack {
                            if store.isCreatingVault || store.isImportingVault || store.isUnlockingVault {
                                ProgressView().tint(midnight)
                            } else {
                                Image(systemName: "lock.fill")
                            }
                            Text(importing ? (store.isImportingVault ? "Uvoz trezora…" : "Uvezi trezor") : (creating ? (store.isCreatingVault ? "Izrada trezora…" : "Izradi trezor") : (store.isUnlockingVault ? "Otključavanje…" : "Otključaj"))).fontWeight(.bold)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 54)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(midnight)
                    .background(importing && importPayload == nil ? cyan.opacity(0.35) : cyan)
                    .clipShape(Capsule())
                    .disabled(store.isCreatingVault || store.isImportingVault || store.isUnlockingVault || (importing && importPayload == nil))

                    if creating {
                        Button {
                            store.cancelSetup()
                        } label: {
                            Label("Natrag", systemImage: "chevron.left")
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 8)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(ice)
                    }

                    if !creating && store.biometricEnabled {
                        Button {
                            store.unlockBiometric()
                        } label: {
                            HStack {
                                Image(systemName: "faceid")
                                Text("Biometrijsko otključavanje")
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.white)
                        .overlay(Capsule().stroke(cyan.opacity(0.6), lineWidth: 1))
                    }
                }
            }
            .padding(compact ? 16 : 24)
            }
        }
        .fileImporter(
            isPresented: $showImportPicker,
            allowedContentTypes: KeyraBackupDocument.readableContentTypes,
            allowsMultipleSelection: false
        ) { result in
            do {
                guard let url = try result.get().first else { return }
                let accessed = url.startAccessingSecurityScopedResource()
                defer { if accessed { url.stopAccessingSecurityScopedResource() } }
                let text = try readLimitedKeyraText(url, maxBytes: 2_500_000)
                if text.isEmpty {
                    importPayload = nil
                    store.message = "Sigurnosna kopija nije valjana ili je prevelika."
                    return
                }
                importPayload = text
                store.message = "Šifrirana sigurnosna kopija je učitana."
            } catch {
                importPayload = nil
                store.message = "Sigurnosnu kopiju nije moguće otvoriti."
            }
        }
    }
}

struct SecretField: View {
    let title: String
    @Binding var text: String
    @Binding var reveal: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "lock.fill")
                .foregroundStyle(cyan)
                .frame(width: 24)

            Group {
                if reveal {
                    TextField(title, text: $text)
                } else {
                    SecureField(title, text: $text)
                }
            }
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()

            Button { reveal.toggle() } label: {
                Image(systemName: reveal ? "eye.slash" : "eye")
                    .foregroundStyle(ice)
                    .frame(width: 32, height: 32)
                    .background(midnight.opacity(0.48))
                    .clipShape(Circle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel(reveal ? "Sakrij \(title)" : "Prikaži \(title)")
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 56)
        .background(
            LinearGradient(
                colors: [slate2.opacity(0.88), slate.opacity(0.72)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(ice.opacity(0.24), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 18))
        .foregroundStyle(.white)
    }
}

struct BottomBar: View {
    @EnvironmentObject var store: KeyraStore

    var body: some View {
        HStack(spacing: 4) {
            BottomItem(icon: "house.fill", title: "Trezor", screen: .vault)
            BottomItem(icon: "square.grid.2x2.fill", title: "Kolekcije", screen: .collections)
            BottomItem(icon: "arrow.triangle.2.circlepath", title: "Generator", screen: .generator)
            BottomItem(icon: "gearshape.fill", title: "Postavke", screen: .settings)
        }
        .padding(6)
        .background(
            LinearGradient(
                colors: [slate2.opacity(0.99), slate.opacity(0.98)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .overlay(RoundedRectangle(cornerRadius: 26).stroke(cyan.opacity(0.22), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 26))
        .shadow(color: .black.opacity(0.28), radius: 12, y: 7)
        .padding(.horizontal, 12)
        .padding(.bottom, 4)
        .frame(maxWidth: 820)
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder
    private func BottomItem(icon: String, title: String, screen: KeyraScreen) -> some View {
        let selected = store.screen == screen
        Button {
            store.open(screen)
        } label: {
            VStack(spacing: 3) {
                Image(systemName: icon)
                    .font(.system(size: 19, weight: .semibold))
                Text(title)
                    .font(.caption2)
                    .fontWeight(selected ? .bold : .medium)
                    .lineLimit(1)
                    .minimumScaleFactor(0.72)
                Capsule()
                    .fill(cyan)
                    .frame(width: selected ? 26 : 0, height: 2)
            }
            .foregroundStyle(selected ? cyan : muted)
            .frame(maxWidth: .infinity, minHeight: 48)
            .background(
                selected
                    ? LinearGradient(
                        colors: [cyan.opacity(0.17), indigo.opacity(0.10)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                    : LinearGradient(colors: [.clear, .clear], startPoint: .leading, endPoint: .trailing)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .stroke(selected ? cyan.opacity(0.36) : Color.clear, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 18))
        }
        .buttonStyle(.plain)
    }
}

struct VaultView: View {
    @EnvironmentObject var store: KeyraStore
    @State private var search = ""
    @State private var filter = "Sve"
    @State private var newestFirst = true

    private var passwordItems: [VaultItem] {
        store.items.filter { $0.kind == "Prijava" || $0.kind == "Wi-Fi" }
    }

    private var duplicates: Set<UUID> {
        let grouped = Dictionary(grouping: passwordItems.filter { !$0.password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }, by: { $0.password })
        return Set(grouped.values.filter { $0.count > 1 }.flatMap { $0.map(\.id) })
    }

    private var filtered: [VaultItem] {
        store.items
            .filter { item in
                let typeOK: Bool
                switch filter {
                case "Sve": typeOK = true
                case "Favoriti": typeOK = item.favorite
                default: typeOK = item.kind == filter
                }

                let haystack = [
                    item.title,
                    item.username,
                    item.website,
                    item.notes,
                    item.category,
                    item.extraFields.values.joined(separator: " ")
                ].joined(separator: " ")

                let searchOK = search.isEmpty || haystack.localizedCaseInsensitiveContains(search)
                let categoryOK = store.vaultCategoryFilter == nil || item.category == store.vaultCategoryFilter
                return typeOK && categoryOK && searchOK
            }
            .sorted {
                newestFirst
                ? $0.updatedAt > $1.updatedAt
                : $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending
            }
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "MOJ TREZOR")

            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(ice)
                TextField("Pretražite svoj trezor...", text: $search)
                    .foregroundStyle(.white)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if !search.isEmpty {
                    Button {
                        search = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(muted)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Očisti pretragu")
                }
            }
            .padding()
            .background(slate)
            .overlay(RoundedRectangle(cornerRadius: 24).stroke(ice.opacity(0.35), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 24))
            .padding(.horizontal, 18)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(["Sve","Prijava","Bilješka","Kartica","Identitet","Wi-Fi","Autentifikator","Favoriti"], id: \.self) { value in
                        Button {
                            filter = value
                        } label: {
                            HStack(spacing: 6) {
                                Image(systemName: {
                                    switch value {
                                    case "Prijava": return "lock.fill"
                                    case "Bilješka": return "doc.text"
                                    case "Kartica": return "creditcard"
                                    case "Identitet": return "person.text.rectangle"
                                    case "Wi-Fi": return "wifi"
                                    case "Autentifikator": return "shield.lefthalf.filled"
                                    case "Favoriti": return "star"
                                    default: return "square.grid.2x2"
                                    }
                                }())
                                Text({
                                    switch value {
                                    case "Prijava": return "Prijave"
                                    case "Bilješka": return "Bilješke"
                                    case "Kartica": return "Kartice"
                                    case "Autentifikator": return "2FA"
                                    default: return value
                                    }
                                }())
                            }
                            .foregroundStyle(filter == value ? midnight : .white)
                            .padding(.horizontal, 14)
                            .padding(.vertical, 9)
                            .background(filter == value ? cyan : slate)
                            .clipShape(Capsule())
                            .overlay(Capsule().stroke(ice.opacity(0.25), lineWidth: 1))
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
            }

            if let category = store.vaultCategoryFilter {
                HStack {
                    HStack(spacing: 5) {
                        Text("Kategorija: \(category.isEmpty ? "Bez kategorije" : category)")
                            .font(.caption)
                            .foregroundStyle(cyan)
                        Button {
                            store.clearVaultCategoryFilter()
                        } label: {
                            Image(systemName: "xmark")
                                .font(.caption.bold())
                                .foregroundStyle(cyan)
                                .frame(width: 26, height: 26)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Ukloni filtar")
                    }
                    .padding(.leading, 11)
                    .padding(.trailing, 3)
                    .padding(.vertical, 3)
                    .background(cyan.opacity(0.12))
                    .overlay(Capsule().stroke(cyan.opacity(0.55), lineWidth: 1))
                    .clipShape(Capsule())
                    Spacer()
                }
                .padding(.horizontal, 18)
                .padding(.bottom, 5)
            }

            ViewThatFits(in: .horizontal) {
                HStack(spacing: 10) {
                    Summary(value: "\(store.items.count)", label: "Ukupno", accent: cyan)
                    Summary(value: "\(securityIssueCount(store.items))", label: "Rizične", accent: danger)
                    Summary(value: "\(duplicates.count)", label: "Ponovljene", accent: indigo)
                }

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        Summary(value: "\(store.items.count)", label: "Ukupno", accent: cyan).frame(width: 112)
                        Summary(value: "\(securityIssueCount(store.items))", label: "Rizične", accent: danger).frame(width: 112)
                        Summary(value: "\(duplicates.count)", label: "Ponovljene", accent: indigo).frame(width: 124)
                    }
                }
            }
            .padding(.horizontal, 14)

            HStack {
                Text("Vaše stavke")
                    .font(.system(size: 28, weight: .black))
                    .foregroundStyle(.white)
                Spacer()
                Button {
                    newestFirst.toggle()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: newestFirst ? "clock" : "textformat.abc")
                        Text(newestFirst ? "Najnovije" : "A–Ž")
                    }
                    .font(.caption)
                    .foregroundStyle(muted)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Sortiraj stavke: \(newestFirst ? "Najnovije" : "A–Ž")")

                Button { store.addNew() } label: {
                    Image(systemName: "plus")
                        .font(.title2.bold())
                        .foregroundStyle(midnight)
                        .frame(width: 44, height: 44)
                        .background(cyan)
                        .clipShape(Circle())
                }
                .accessibilityLabel("Dodaj stavku")
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 12)

            ScrollView {
                LazyVStack(spacing: 9) {
                    ForEach(filtered) { item in
                        Button {
                            store.select(item)
                        } label: {
                            VaultRow(item: item, duplicated: duplicates.contains(item.id))
                        }
                        .buttonStyle(.plain)
                        .accessibilityHint("Otvori stavku")
                    }
                    if filtered.isEmpty {
                        GlassCard {
                            Image(systemName: store.items.isEmpty ? "plus.circle" : "magnifyingglass")
                                .font(.title2)
                                .foregroundStyle(cyan)
                            Text(store.items.isEmpty ? "Vaš trezor je spreman" : "Nema rezultata")
                                .font(.title3.bold())
                                .foregroundStyle(.white)
                            Text(
                                store.items.isEmpty
                                ? "Dodajte prvu prijavu, bilješku, karticu, identitet, Wi‑Fi ili 2FA autentifikator."
                                : "Promijenite pretragu ili odaberite drugi filtar."
                            )
                            .foregroundStyle(muted)

                            if store.items.isEmpty {
                                Button {
                                    store.addNew()
                                } label: {
                                    Label("Dodaj prvu stavku", systemImage: "plus")
                                        .fontWeight(.bold)
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 11)
                                }
                                .buttonStyle(.plain)
                                .foregroundStyle(midnight)
                                .background(cyan)
                                .clipShape(Capsule())
                            } else {
                                Button {
                                    search = ""
                                    filter = "Sve"
                                    store.clearVaultCategoryFilter()
                                } label: {
                                    Text("Očisti filtre")
                                        .fontWeight(.bold)
                                        .frame(maxWidth: .infinity)
                                        .padding(.vertical, 11)
                                }
                                .buttonStyle(.plain)
                                .foregroundStyle(midnight)
                                .background(cyan)
                                .clipShape(Capsule())
                            }
                        }
                        .padding(.top, 20)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.bottom, 100)
            }
        }
        .onAppear {
            if let pendingType = store.vaultTypeFilter {
                filter = pendingType
            }
        }
    }
}

struct Summary: View {
    let value: String
    let label: String
    let accent: Color

    private var icon: String {
        switch label {
        case "Rizične": return "exclamationmark.triangle.fill"
        case "Ponovljene": return "doc.on.doc.fill"
        default: return "shield.fill"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .bold))
                    .foregroundStyle(accent)
                    .frame(width: 30, height: 30)
                    .background(accent.opacity(0.13))
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                Spacer()
                Circle()
                    .fill(accent)
                    .frame(width: 7, height: 7)
            }
            Text(value)
                .font(.system(size: 30, weight: .black, design: .rounded))
                .foregroundStyle(.white)
            Text(label.uppercased())
                .font(.system(size: 10, weight: .semibold))
                .tracking(0.8)
                .foregroundStyle(muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(
            LinearGradient(
                colors: [slate2.opacity(0.98), slate.opacity(0.92)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .overlay(RoundedRectangle(cornerRadius: 22).stroke(accent.opacity(0.42), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 22))
        .shadow(color: .black.opacity(0.16), radius: 6, y: 3)
    }
}

struct VaultRow: View {
    let item: VaultItem
    let duplicated: Bool

    private var isPasswordItem: Bool { item.kind == "Prijava" || item.kind == "Wi-Fi" }

    private var state: (String, Color) {
        if item.kind == "Kartica" && cardExpiryNeedsAttention(item.extraFields["Vrijedi do"] ?? "") {
            return ("Provjeri istek", warn)
        }
        if item.kind == "Autentifikator" && totpConfigFromFields(item.extraFields) == nil {
            return ("TOTP greška", danger)
        }
        if duplicated { return ("Ponovno korištena", danger) }
        if isPasswordItem && item.password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return ("Bez lozinke", warn) }
        if isPasswordItem && !item.password.isEmpty && !isStrongPassword(item.password) { return ("Potrebno ažuriranje", warn) }
        switch item.kind {
        case "Bilješka", "Kartica": return ("Zaštićena", good)
        case "Identitet": return ("Zaštićen", good)
        case "Autentifikator": return ("2FA aktivan", good)
        default: return ("Snažna", good)
        }
    }

    private var icon: String {
        switch item.kind {
        case "Bilješka": return "doc.text.fill"
        case "Kartica": return "creditcard.fill"
        case "Identitet": return "person.text.rectangle.fill"
        case "Wi-Fi": return "wifi"
        case "Autentifikator": return "shield.lefthalf.filled"
        default: return "lock.fill"
        }
    }

    private var accent: Color {
        switch item.kind {
        case "Bilješka": return indigo
        case "Kartica": return warn
        case "Identitet": return Color(hex: 0xB48CFF)
        case "Wi-Fi": return Color(hex: 0x22BDF7)
        case "Autentifikator": return good
        default: return cyan
        }
    }

    private var subtitle: String {
        switch item.kind {
        case "Kartica":
            if let number = item.extraFields["Broj kartice"], !number.isEmpty {
                let asciiDigits = Set("0123456789")
                let suffix = number.filter { asciiDigits.contains($0) }.suffix(4)
                if !suffix.isEmpty { return "•••• " + String(suffix) }
            }
            return item.category
        case "Identitet":
            return item.extraFields["Puno ime"]?.isEmpty == false ? item.extraFields["Puno ime"]! : item.category
        case "Wi-Fi":
            if let network = item.extraFields["Naziv mreže"], !network.isEmpty { return network }
            return item.username.isEmpty ? item.category : item.username
        case "Autentifikator":
            if let account = item.extraFields["Račun"], !account.isEmpty { return account }
            if let issuer = item.extraFields["Izdavatelj"], !issuer.isEmpty { return issuer }
            return item.category
        case "Bilješka":
            return item.category
        default:
            if !item.username.isEmpty { return item.username }
            if !item.website.isEmpty { return item.website }
            return item.category
        }
    }

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) {
                vaultIcon
                vaultIdentity
                Spacer(minLength: 8)
                statusChip
            }

            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    vaultIcon
                    vaultIdentity
                }
                HStack {
                    Spacer()
                    statusChip
                }
            }
        }
        .padding(14)
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(ice.opacity(0.18), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }

    private var vaultIcon: some View {
        Image(systemName: icon)
            .font(.title3.bold())
            .foregroundStyle(accent)
            .frame(width: 48, height: 48)
            .background(accent.opacity(0.16))
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private var vaultIdentity: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(item.title)
                .font(.headline)
                .foregroundStyle(.white)
                .lineLimit(1)
                .minimumScaleFactor(0.78)
            Text(subtitle)
                .font(.subheadline)
                .foregroundStyle(muted)
                .lineLimit(1)
                .minimumScaleFactor(0.78)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var statusChip: some View {
        Text(state.0)
            .font(.caption)
            .foregroundStyle(state.1)
            .lineLimit(1)
            .minimumScaleFactor(0.72)
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .background(state.1.opacity(0.12))
            .overlay(Capsule().stroke(state.1.opacity(0.8), lineWidth: 1))
            .clipShape(Capsule())
    }
}

struct CollectionsView: View {
    @EnvironmentObject var store: KeyraStore
    @State private var search = ""
    @State private var selectedType = "Sve"

    let categories: [(String, Color, String)] = [
        ("Osobno", Color(hex: 0x00AEE8), "person.fill"),
        ("Posao", indigo, "briefcase.fill"),
        ("Financije", Color(hex: 0x00D8A1), "creditcard.fill"),
        ("Društvene mreže", Color(hex: 0xFF3A7A), "person.2.fill"),
        ("Kupovina", Color(hex: 0xFFC026), "cart.fill"),
        ("Putovanja", Color(hex: 0x00B8FF), "airplane"),
        ("Zdravlje", Color(hex: 0x9C6CFF), "heart.fill"),
        ("Ostalo", muted, "square.grid.2x2")
    ]

    private var collectionItems: [VaultItem] {
        store.items.filter { item in
            let typeMatch: Bool
            switch selectedType {
            case "Sve": typeMatch = true
            case "Favoriti": typeMatch = item.favorite
            default: typeMatch = item.kind == selectedType
            }
            let haystack = [
                item.title,
                item.username,
                item.website,
                item.notes,
                item.category,
                item.extraFields.values.joined(separator: " ")
            ].joined(separator: " ")
            let searchMatch = search.isEmpty || haystack.localizedCaseInsensitiveContains(search)
            return typeMatch && searchMatch
        }
    }

    private var visibleCategories: [(String, Color, String)] {
        let present = Set(collectionItems.map(\.category))
        let known = Set(categories.map { $0.0 })
        let imported = present.subtracting(known).sorted().map { ($0, muted, "folder.fill") }
        return categories.filter { present.contains($0.0) } + imported
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "KOLEKCIJE")

            HStack {
                Text("Organizirajte trezor po vrsti i kategoriji.")
                    .font(.subheadline)
                    .foregroundStyle(muted)
                Spacer()
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 4)

            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(ice)
                TextField("Pretražite lozinke, bilješke, kartice...", text: $search)
                    .foregroundStyle(.white)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                if !search.isEmpty {
                    Button {
                        search = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill").foregroundStyle(muted)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Očisti pretragu")
                }
            }
            .padding()
            .background(slate)
            .overlay(RoundedRectangle(cornerRadius: 24).stroke(ice.opacity(0.35), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 24))
            .padding(.horizontal, 18)
            .padding(.top, 10)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(["Sve","Prijava","Bilješka","Kartica","Identitet","Wi-Fi","Autentifikator","Favoriti"], id: \.self) { value in
                        Button {
                            selectedType = value
                        } label: {
                            Text({
                                switch value {
                                case "Prijava": return "Lozinke"
                                case "Bilješka": return "Bilješke"
                                case "Kartica": return "Kartice"
                                default: return value
                                }
                            }())
                            .foregroundStyle(selectedType == value ? midnight : .white)
                            .padding(.horizontal, 15)
                            .padding(.vertical, 9)
                            .background(selectedType == value ? cyan : slate)
                            .clipShape(Capsule())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
            }

            ScrollView {
                if collectionItems.isEmpty {
                    GlassCard {
                        Text(store.items.isEmpty ? "Vaše kolekcije su prazne" : "Nema rezultata")
                            .font(.headline)
                            .foregroundStyle(.white)
                        Text(store.items.isEmpty
                             ? "Dodajte prvu stavku kako biste vidjeli svoje kolekcije."
                             : "Promijenite pretragu ili odaberite drugi tip.")
                            .foregroundStyle(muted)
                        Button {
                            if store.items.isEmpty {
                                store.addNew()
                            } else {
                                search = ""
                                selectedType = "Sve"
                            }
                        } label: {
                            Text(store.items.isEmpty ? "Dodaj prvu stavku" : "Očisti filtre")
                                .fontWeight(.bold)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 11)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(midnight)
                        .background(cyan)
                        .clipShape(Capsule())
                    }
                    .padding(.horizontal, 18)
                } else {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 150, maximum: 280), spacing: 10)],
                    spacing: 10
                ) {
                    ForEach(visibleCategories.indices, id: \.self) { index in
                        let name = visibleCategories[index].0
                        let accent = visibleCategories[index].1
                        let icon = visibleCategories[index].2
                        HStack(spacing: 10) {
                            Image(systemName: icon)
                                .foregroundStyle(accent)
                                .frame(width: 44, height: 44)
                                .background(accent.opacity(0.18))
                                .clipShape(RoundedRectangle(cornerRadius: 13))
                            VStack(alignment: .leading, spacing: 4) {
                                Text(name.isEmpty ? "Bez kategorije" : name).font(.headline).foregroundStyle(.white)
                                Text("\(collectionItems.filter { $0.category == name }.count) stavki")
                                    .font(.subheadline).foregroundStyle(muted)
                            }
                            Spacer()
                        }
                        .frame(maxWidth: .infinity, minHeight: 58, alignment: .leading)
                        .padding(16)
                        .background(accent.opacity(0.13))
                        .overlay(RoundedRectangle(cornerRadius: 20).stroke(accent.opacity(0.8), lineWidth: 1))
                        .clipShape(RoundedRectangle(cornerRadius: 20))
                        .contentShape(RoundedRectangle(cornerRadius: 20))
                        .onTapGesture {
                            store.openCategory(name, type: selectedType)
                        }
                        .accessibilityElement(children: .combine)
                        .accessibilityAddTraits(.isButton)
                        .accessibilityAction {
                            store.openCategory(name, type: selectedType)
                        }
                    }
                }
                .padding(.horizontal, 18)
                }

                Spacer(minLength: 18)
                    .frame(height: 18)
            }
            .padding(.bottom, 100)
        }
    }
}

struct GeneratorView: View {
    @EnvironmentObject var store: KeyraStore
    @State private var length = 16.0
    @State private var upper = true
    @State private var lower = true
    @State private var numbers = true
    @State private var symbols = true
    @State private var password = PasswordTools.generate(length: 16, upper: true, lower: true, numbers: true, symbols: true)

    private var presetName: String {
        if length == 12 && upper && lower && numbers && !symbols { return "Jednostavna" }
        if length == 16 && upper && lower && numbers && symbols { return "Snažna" }
        if length == 32 && upper && lower && numbers && symbols { return "Maksimalna" }
        return "Prilagodi"
    }

    private func applyPreset(_ name: String) {
        switch name {
        case "Jednostavna":
            length = 12
            upper = true
            lower = true
            numbers = true
            symbols = false
        case "Maksimalna":
            length = 32
            upper = true
            lower = true
            numbers = true
            symbols = true
        default:
            length = 16
            upper = true
            lower = true
            numbers = true
            symbols = true
        }
        refresh()
    }

    private func refresh() {
        password = PasswordTools.generate(length: Int(length), upper: upper, lower: lower, numbers: numbers, symbols: symbols)
    }

    private func updateCharacterSet(_ name: String, enabled: Bool) {
        let activeCount = [upper, lower, numbers, symbols].filter { $0 }.count
        let currentValue: Bool
        switch name {
        case "upper": currentValue = upper
        case "lower": currentValue = lower
        case "numbers": currentValue = numbers
        default: currentValue = symbols
        }

        if currentValue && !enabled && activeCount <= 1 {
            store.message = "Generator mora koristiti barem jednu vrstu znakova."
            return
        }

        switch name {
        case "upper": upper = enabled
        case "lower": lower = enabled
        case "numbers": numbers = enabled
        default: symbols = enabled
        }
        refresh()
    }

    private var entropyBits: Int {
        let pool = (upper ? 26 : 0) + (lower ? 26 : 0) + (numbers ? 10 : 0) + (symbols ? 15 : 0)
        guard pool > 1 else { return 0 }
        return Int(Double(length) * log2(Double(pool)))
    }

    private var strengthProgress: Double {
        min(max(Double(entropyBits) / 128.0, 0.08), 1.0)
    }

    private var strengthLabel: String {
        switch entropyBits {
        case 100...: return "Vrlo snažna"
        case 75...: return "Snažna"
        case 50...: return "Srednja"
        default: return "Slaba"
        }
    }

    private var strengthColor: Color {
        entropyBits >= 75 ? good : (entropyBits >= 50 ? warn : danger)
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "Generator lozinki")
            ScrollView {
                VStack(spacing: 12) {
                    GlassCard {
                        Text("Generirajte sigurnu lozinku")
                            .font(.title2.bold())
                            .foregroundStyle(.white)
                        Text("Izradite snažne, jedinstvene lozinke u nekoliko sekundi.")
                            .foregroundStyle(muted)
                        Text(password)
                            .font(.system(size: 22, weight: .bold, design: .monospaced))
                            .foregroundStyle(.white)
                            .lineLimit(3)
                            .minimumScaleFactor(0.75)
                            .fixedSize(horizontal: false, vertical: true)
                        ProgressView(value: strengthProgress)
                            .tint(strengthColor)
                        HStack {
                            Text(strengthLabel).fontWeight(.bold).foregroundStyle(strengthColor)
                            Spacer()
                            Text("~\(entropyBits) bita entropije")
                                .font(.caption)
                                .foregroundStyle(muted)
                        }
                    }

                    GlassCard {
                        Text("Postavke lozinke")
                            .font(.headline)
                            .foregroundStyle(.white)
                        Text("Odaberite preset ili prilagodite duljinu i vrste znakova.")
                            .font(.subheadline)
                            .foregroundStyle(muted)

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(["Jednostavna", "Snažna", "Maksimalna"], id: \.self) { name in
                                    Button(name) {
                                        applyPreset(name)
                                    }
                                    .buttonStyle(.plain)
                                    .foregroundStyle(presetName == name ? midnight : .white)
                                    .padding(.horizontal, 13)
                                    .padding(.vertical, 8)
                                    .background(presetName == name ? cyan : slate2)
                                    .overlay(Capsule().stroke(cyan.opacity(presetName == name ? 0 : 0.45), lineWidth: 1))
                                    .clipShape(Capsule())
                                }
                            }
                        }

                        Divider().overlay(ice.opacity(0.14))

                        HStack {
                            Text("Duljina")
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.white)
                            Spacer()
                            Text("\(Int(length))")
                                .font(.subheadline.bold())
                                .foregroundStyle(cyan)
                                .padding(.horizontal, 10)
                                .padding(.vertical, 5)
                                .background(cyan.opacity(0.12))
                                .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                        Slider(value: $length, in: 8...64, step: 1)
                            .tint(cyan)
                            .onChange(of: length) { _, _ in refresh() }

                        Divider().overlay(ice.opacity(0.14))

                        Text("Vrste znakova")
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.white)
                        GeneratorToggle(title: "Velika slova (A–Z)", value: upper) {
                            updateCharacterSet("upper", enabled: $0)
                        }
                        GeneratorToggle(title: "Mala slova (a–z)", value: lower) {
                            updateCharacterSet("lower", enabled: $0)
                        }
                        GeneratorToggle(title: "Brojevi (0–9)", value: numbers) {
                            updateCharacterSet("numbers", enabled: $0)
                        }
                        GeneratorToggle(title: "Simboli (!@#...)", value: symbols) {
                            updateCharacterSet("symbols", enabled: $0)
                        }
                    }

                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: 10) {
                            generatorCopyButton
                            generatorRefreshButton
                        }
                        VStack(spacing: 8) {
                            generatorRefreshButton
                            generatorCopyButton
                        }
                    }
                }
                .padding(18)
                .padding(.bottom, 90)
            }
        }
    }

    private var generatorCopyButton: some View {
        Button {
            SecureClipboard.copy(password)
            store.message = "Lozinka je kopirana i automatski će se ukloniti."
        } label: {
            Label("Kopiraj lozinku", systemImage: "doc.on.doc")
                .fontWeight(.bold)
                .frame(maxWidth: .infinity)
                .frame(height: 54)
        }
        .buttonStyle(.plain)
        .foregroundStyle(.white)
        .overlay(Capsule().stroke(cyan.opacity(0.7), lineWidth: 1))
    }

    private var generatorRefreshButton: some View {
        Button {
            refresh()
        } label: {
            Label("Generiraj novu", systemImage: "arrow.triangle.2.circlepath")
                .fontWeight(.bold)
                .frame(maxWidth: .infinity)
                .frame(height: 54)
        }
        .buttonStyle(.plain)
        .foregroundStyle(midnight)
        .background(cyan)
        .clipShape(Capsule())
    }
}

struct GeneratorToggle: View {
    let title: String
    let value: Bool
    let onChange: (Bool) -> Void

    var body: some View {
        Toggle(
            title,
            isOn: Binding(
                get: { value },
                set: onChange
            )
        )
        .tint(cyan)
        .foregroundStyle(.white)
    }
}

struct AddEditView: View {
    @ObservedObject var store: KeyraStore
    @State private var title: String
    @State private var website: String
    @State private var username: String
    @State private var password: String
    @State private var notes: String
    @State private var category: String
    @State private var favorite: Bool
    @State private var type: String
    @State private var field1: String
    @State private var field2: String
    @State private var field3: String
    @State private var field4: String
    @State private var totpAlgorithm: String
    @State private var totpDigits: Int
    @State private var totpPeriod: Int
    @State private var reveal = false

    private let original: VaultItem?

    private var categoryOptions: [String] {
        let standard = ["Osobno", "Posao", "Financije", "Društvene mreže", "Kupovina", "Putovanja", "Zdravlje", "Ostalo"]
        let other = Set(store.items.map(\.category) + [category])
            .subtracting(standard)
            .sorted { $0.localizedCaseInsensitiveCompare($1) == .orderedAscending }
        return standard + other
    }

    private var itemLabel: String {
        switch type {
        case "Bilješka": return "bilješku"
        case "Kartica": return "karticu"
        case "Identitet": return "identitet"
        case "Wi-Fi": return "Wi-Fi"
        case "Autentifikator": return "autentifikator"
        default: return "prijavu"
        }
    }

    private var screenTitle: String {
        original == nil ? "Dodaj \(itemLabel)" : "Uredi \(itemLabel)"
    }

    private var screenSubtitle: String {
        switch type {
        case "Bilješka": return "Sigurno spremite privatne bilješke i osjetljive informacije"
        case "Kartica": return "Zaštitite podatke kartice i držite ih na jednom mjestu"
        case "Identitet": return "Sigurno spremite podatke identiteta i dokumenata"
        case "Wi-Fi": return "Spremite naziv mreže, zaštitu i pristupne podatke"
        case "Autentifikator": return "Generirajte vremenski 2FA kod koji se automatski mijenja"
        default: return "Sigurno spremite svoje vjerodajnice"
        }
    }

    private var saveLabel: String {
        switch type {
        case "Bilješka": return "Spremi bilješku"
        case "Kartica": return "Spremi karticu"
        case "Identitet": return "Spremi identitet"
        case "Wi-Fi": return "Spremi Wi-Fi"
        case "Autentifikator": return "Spremi autentifikator"
        default: return "Spremi prijavu"
        }
    }

    private var totpPreview: TotpConfig? {
        guard type == "Autentifikator" else { return nil }
        return parseTotpInput(
            field3,
            fallbackIssuer: field1,
            fallbackAccount: field2,
            fallbackAlgorithm: totpAlgorithm,
            fallbackDigits: totpDigits,
            fallbackPeriod: totpPeriod
        )
    }

    init(store: KeyraStore) {
        self.store = store
        let item = store.selected
        self.original = item
        _title = State(initialValue: item?.title ?? "")
        _website = State(initialValue: item?.website ?? "")
        _username = State(initialValue: item?.username ?? "")
        _password = State(initialValue: item?.password ?? "")
        _notes = State(initialValue: item?.notes ?? "")
        _category = State(initialValue: item?.category ?? "Osobno")
        _favorite = State(initialValue: item?.favorite ?? false)
        _type = State(initialValue: item?.kind ?? "Prijava")

        let extra = item?.extraFields ?? [:]
        _totpAlgorithm = State(initialValue: extra["Algoritam"] ?? "SHA1")
        _totpDigits = State(initialValue: Int(extra["Znamenke"] ?? "") ?? 6)
        _totpPeriod = State(initialValue: Int(extra["Period"] ?? "") ?? 30)

        switch item?.kind {
        case "Kartica":
            _field1 = State(initialValue: extra["Vlasnik kartice"] ?? "")
            let storedCardNumber = extra["Broj kartice"] ?? ""
            _field2 = State(initialValue: isValidCardNumber(storedCardNumber)
                ? formatCardNumberInput(storedCardNumber) : storedCardNumber)
            _field3 = State(initialValue: extra["Vrijedi do"] ?? "")
            _field4 = State(initialValue: extra["Sigurnosni kod"] ?? "")
        case "Identitet":
            _field1 = State(initialValue: extra["Puno ime"] ?? "")
            _field2 = State(initialValue: extra["Broj dokumenta"] ?? "")
            _field3 = State(initialValue: extra["Datum isteka"] ?? "")
            _field4 = State(initialValue: "")
        case "Wi-Fi":
            _field1 = State(initialValue: extra["Naziv mreže"] ?? "")
            _field2 = State(initialValue: extra["Vrsta zaštite"] ?? "")
            _field3 = State(initialValue: "")
            _field4 = State(initialValue: "")
        case "Autentifikator":
            _field1 = State(initialValue: extra["Izdavatelj"] ?? "")
            _field2 = State(initialValue: extra["Račun"] ?? "")
            _field3 = State(initialValue: extra["TOTP tajna"] ?? "")
            _field4 = State(initialValue: "")
        default:
            _field1 = State(initialValue: "")
            _field2 = State(initialValue: "")
            _field3 = State(initialValue: "")
            _field4 = State(initialValue: "")
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Button {
                    store.open(original == nil ? .vault : .detail)
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.headline.bold())
                        .foregroundStyle(.white)
                        .frame(width: 40, height: 40)
                        .background(midnight.opacity(0.72))
                        .clipShape(Circle())
                }
                .buttonStyle(.plain)

                KeyraMark(size: 36)

                VStack(alignment: .leading, spacing: 1) {
                    Text("Keyra")
                        .font(.system(size: 24, weight: .black, design: .rounded))
                        .foregroundStyle(.white)
                    Text(original == nil ? "NOVA STAVKA" : "UREĐIVANJE STAVKE")
                        .font(.system(size: 9, weight: .semibold))
                        .tracking(1.4)
                        .foregroundStyle(muted)
                }
                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 10)
            .background(
                LinearGradient(
                    colors: [slate2.opacity(0.98), Color(hex: 0x101B2F).opacity(0.98)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .overlay(RoundedRectangle(cornerRadius: 24).stroke(cyan.opacity(0.24), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 24))
            .shadow(color: .black.opacity(0.18), radius: 7, y: 4)
            .padding(.horizontal, 12)
            .padding(.top, 8)

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(screenTitle)
                        .font(.system(size: 38, weight: .black))
                        .foregroundStyle(.white)
                    Text(screenSubtitle)
                        .foregroundStyle(muted)

                    Text("VRSTA STAVKE")
                        .font(.caption)
                        .tracking(2)
                        .foregroundStyle(ice)

                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack {
                            ForEach(["Prijava","Bilješka","Kartica","Identitet","Wi-Fi","Autentifikator"], id: \.self) { value in
                                Button {
                                    if original == nil {
                                        type = value
                                        field1 = ""
                                        field2 = ""
                                        field3 = ""
                                        field4 = ""
                                        totpAlgorithm = "SHA1"
                                        totpDigits = 6
                                        totpPeriod = 30
                                    }
                                } label: {
                                    HStack(spacing: 6) {
                                        Image(systemName: {
                                            switch value {
                                            case "Bilješka": return "doc.text"
                                            case "Kartica": return "creditcard"
                                            case "Identitet": return "person.text.rectangle"
                                            case "Wi-Fi": return "wifi"
                                            case "Autentifikator": return "shield.lefthalf.filled"
                                            default: return "lock"
                                            }
                                        }())
                                        Text(value)
                                    }
                                    .foregroundStyle(type == value ? midnight : .white)
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 9)
                                    .background(type == value ? cyan : slate)
                                    .clipShape(Capsule())
                                    .opacity(original == nil || type == value ? 1 : 0.45)
                                }
                                .buttonStyle(.plain)
                                .disabled(original != nil && type != value)
                            }
                        }
                    }

                    KeyraField(title: "Naslov", text: $title)

                    if type == "Prijava" {
                        KeyraField(title: "Web-stranica", text: $website)
                        KeyraField(title: "Korisničko ime / e-pošta", text: $username)
                        SecretField(title: "Lozinka", text: $password, reveal: $reveal)

                        Button {
                            password = PasswordTools.generate(length: 18, upper: true, lower: true, numbers: true, symbols: true)
                        } label: {
                            Label("Generiraj", systemImage: "arrow.triangle.2.circlepath")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(cyan)
                    }

                    if type == "Wi-Fi" {
                        KeyraField(title: "Naziv mreže", text: $field1)
                        KeyraField(title: "Korisničko ime (nije obavezno)", text: $username)
                        SecretField(title: "Lozinka mreže", text: $password, reveal: $reveal)
                        Button {
                            password = PasswordTools.generate(length: 20, upper: true, lower: true, numbers: true, symbols: true)
                        } label: {
                            Label("Generiraj", systemImage: "arrow.triangle.2.circlepath")
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(cyan)
                        KeyraField(title: "Vrsta zaštite, npr. WPA3", text: $field2)
                    }

                    if type == "Kartica" {
                        KeyraField(title: "Vlasnik kartice", text: $field1)
                        KeyraField(title: "Broj kartice (razmaci se dodaju automatski)", text: $field2)
                            .keyboardType(.numberPad)
                            .onChange(of: field2) { _, value in
                                let formatted = formatCardNumberInput(value)
                                if formatted != value { field2 = formatted }
                            }
                        KeyraField(title: "Vrijedi do (MM/GG)", text: $field3)
                            .keyboardType(.numberPad)
                            .onChange(of: field3) { _, value in
                                let formatted = formatCardExpiry(value)
                                if formatted != value {
                                    field3 = formatted
                                }
                            }
                        SecretField(title: "Sigurnosni kod (3–4 znamenke)", text: $field4, reveal: $reveal)
                            .keyboardType(.numberPad)
                            .onChange(of: field4) { _, value in
                                let asciiDigits = Set("0123456789")
                                let clean = String(value.filter { asciiDigits.contains($0) }.prefix(4))
                                if clean != value { field4 = clean }
                            }
                    }

                    if type == "Identitet" {
                        KeyraField(title: "Puno ime", text: $field1)
                        KeyraField(title: "Broj dokumenta", text: $field2)
                        KeyraField(title: "Datum isteka", text: $field3)
                    }

                    if type == "Autentifikator" {
                        KeyraField(title: "Izdavatelj / servis", text: $field1)
                        KeyraField(title: "Račun / e-pošta", text: $field2)
                        SecretField(title: "TOTP tajna ili otpauth:// URI", text: $field3, reveal: $reveal)

                        if let config = totpPreview {
                            Text("TOTP • \(config.algorithm) • \(config.digits) znamenki • \(config.period) s")
                                .font(.caption)
                                .foregroundStyle(good)
                        } else if !field3.isEmpty {
                            Text("Tajna mora biti Base32 ili valjani otpauth://totp URI.")
                                .font(.caption)
                                .foregroundStyle(warn)
                        }

                        if field3.lowercased().hasPrefix("otpauth://"), let config = totpPreview {
                            Button {
                                field1 = config.issuer
                                field2 = config.account
                                if title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                    title = config.issuer.isEmpty ? config.account : config.issuer
                                }
                                field3 = config.secret
                                totpAlgorithm = config.algorithm
                                totpDigits = config.digits
                                totpPeriod = config.period
                                store.message = "Podaci autentifikatora učitani su iz otpauth URI-ja."
                            } label: {
                                Label("Učitaj podatke iz URI-ja", systemImage: "square.and.arrow.down")
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(cyan)
                        }

                        Text("Kompatibilno s RFC 6238 TOTP aplikacijama. Kod se obnavlja prema vremenu uređaja.")
                            .font(.caption)
                            .foregroundStyle(muted)
                    }

                    KeyraField(title: "Bilješke (nije obavezno)", text: $notes, axis: .vertical)
                        .onChange(of: notes) { _, value in
                            if value.count > 500 {
                                notes = String(value.prefix(500))
                            }
                        }
                    HStack {
                        Spacer()
                        Text("\(notes.count)/500")
                            .font(.caption2)
                            .foregroundStyle(muted)
                    }

                    Toggle("Dodaj u favorite", isOn: $favorite)
                        .tint(cyan)
                        .foregroundStyle(.white)

                    Text("MAPA / KATEGORIJA")
                        .font(.caption)
                        .tracking(2)
                        .foregroundStyle(ice)

                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack {
                            ForEach(categoryOptions, id: \.self) { value in
                                Button(value.isEmpty ? "Bez kategorije" : value) { category = value }
                                    .buttonStyle(.plain)
                                    .foregroundStyle(category == value ? midnight : .white)
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 9)
                                    .background(category == value ? cyan : slate)
                                    .clipShape(Capsule())
                            }
                        }
                    }

                    KeyraField(title: "Ili upišite vlastitu kategoriju", text: $category)
                        .textInputAutocapitalization(.sentences)
                        .onChange(of: category) { _, value in
                            if value.count > 40 && value != original?.category &&
                               !store.items.contains(where: { $0.category == value }) {
                                category = String(value.prefix(40))
                            }
                        }
                    Text("Naziv kategorije • najviše 40 znakova")
                        .font(.caption)
                        .foregroundStyle(muted)

                    Button {
                        let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
                        let cardDigits = normalizedCardDigits(field2)
                        let validationMessage: String? = {
                            if cleanTitle.isEmpty {
                                return "Unesite naslov stavke."
                            }
                            if type == "Prijava", !website.isEmpty, normalizedWebURL(website) == nil {
                                return "Web-adresa nije valjana. Unesite ispravnu HTTP ili HTTPS adresu."
                            }
                            if type == "Wi-Fi", field1.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                return "Unesite naziv Wi-Fi mreže."
                            }
                            if type == "Kartica", !field2.isEmpty, cardDigits == nil {
                                return "Broj kartice smije sadržavati samo znamenke, razmake i crtice."
                            }
                            if type == "Kartica", !field2.isEmpty, !(12...19).contains(cardDigits?.count ?? 0) {
                                return "Broj kartice mora sadržavati između 12 i 19 znamenki."
                            }
                            if type == "Kartica", !field2.isEmpty, !isValidCardNumber(field2) {
                                return "Broj kartice nije prošao provjeru kontrolne znamenke."
                            }
                            if type == "Kartica", !field4.isEmpty, !isValidCardSecurityCode(field4) {
                                return "Sigurnosni kod mora sadržavati 3 ili 4 znamenke."
                            }
                            if type == "Kartica", !field3.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                let expiry = field3.trimmingCharacters(in: .whitespacesAndNewlines)
                                let pattern = "^(0[1-9]|1[0-2])/(\\d{2}|\\d{4})$"
                                if expiry.range(of: pattern, options: .regularExpression) == nil {
                                    return "Datum isteka kartice unesite u obliku MM/GG ili MM/GGGG."
                                }
                                if !isCardExpiryNotPast(expiry) {
                                    return "Datum isteka kartice je u prošlosti."
                                }
                            }
                            if type == "Identitet",
                               field1.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                               field2.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                return "Unesite puno ime ili broj dokumenta."
                            }
                            if type == "Autentifikator", totpPreview == nil {
                                return "Unesite valjanu Base32 TOTP tajnu ili otpauth:// URI."
                            }
                            return nil
                        }()
                        if let validationMessage {
                            store.message = validationMessage
                            return
                        }
                        guard let savedCategory = resolvedCategoryName(category, original: original?.category, existing: store.items.map(\.category)) else {
                            store.message = "Unesite naziv kategorije."
                            return
                        }

                        let extra: [String: String]
                        switch type {
                        case "Kartica":
                            extra = [
                                "Vlasnik kartice": field1,
                                "Broj kartice": cardDigits ?? "",
                                "Vrijedi do": field3,
                                "Sigurnosni kod": field4
                            ].filter { !$0.value.isEmpty }
                        case "Identitet":
                            extra = [
                                "Puno ime": field1,
                                "Broj dokumenta": field2,
                                "Datum isteka": field3
                            ].filter { !$0.value.isEmpty }
                        case "Wi-Fi":
                            extra = [
                                "Naziv mreže": field1,
                                "Vrsta zaštite": field2
                            ].filter { !$0.value.isEmpty }
                        case "Autentifikator":
                            guard let config = totpPreview else {
                                store.message = "TOTP konfiguracija nije valjana."
                                return
                            }
                            extra = [
                                "Izdavatelj": config.issuer,
                                "Račun": config.account,
                                "TOTP tajna": config.secret,
                                "Algoritam": config.algorithm,
                                "Znamenke": String(config.digits),
                                "Period": String(config.period)
                            ].filter { !$0.value.isEmpty }
                        default:
                            extra = [:]
                        }

                        store.save(
                            VaultItem(
                                id: original?.id ?? UUID(),
                                title: cleanTitle,
                                username: (type == "Prijava" || type == "Wi-Fi") ? username.trimmingCharacters(in: .whitespacesAndNewlines) : "",
                                password: (type == "Prijava" || type == "Wi-Fi") ? password : "",
                                website: type == "Prijava" ? website.trimmingCharacters(in: .whitespacesAndNewlines) : "",
                                notes: String(notes.prefix(500)).trimmingCharacters(in: .whitespacesAndNewlines),
                                category: savedCategory,
                                favorite: favorite,
                                type: type,
                                fields: extra
                            )
                        )
                    } label: {
                        Label(saveLabel, systemImage: "lock.fill")
                            .fontWeight(.bold)
                            .frame(maxWidth: .infinity)
                            .frame(height: 54)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(midnight)
                    .background(cyan)
                    .clipShape(Capsule())
                }
                .padding(18)
                .padding(.bottom, 24)
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }
}

struct KeyraField: View {
    let title: String
    @Binding var text: String
    var axis: Axis = .horizontal

    var body: some View {
        TextField(title, text: $text, axis: axis)
            .lineLimit(axis == .vertical ? 3...6 : 1...1)
            .padding(.horizontal, 14)
            .frame(minHeight: axis == .vertical ? 76 : 56)
            .foregroundStyle(.white)
            .background(
                LinearGradient(
                    colors: [slate2.opacity(0.88), slate.opacity(0.72)],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(ice.opacity(0.24), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 18))
    }
}

struct DetailView: View {
    @EnvironmentObject var store: KeyraStore
    @Environment(\.openURL) private var openURL
    @State private var reveal = false
    @State private var revealCardNumber = false
    @State private var revealSecurityCode = false
    @State private var revealDocumentNumber = false
    @State private var revealTotpSecret = false
    @State private var confirmDelete = false
    @State private var selectedTab = "Detalji"

    var body: some View {
        if let item = store.selected {
            let isPasswordItem = item.kind == "Prijava" || item.kind == "Wi-Fi"
            let totpConfig = item.kind == "Autentifikator" ? totpConfigFromFields(item.extraFields) : nil
            let duplicatedPassword = isPasswordItem &&
                !item.password.isEmpty &&
                store.items.contains {
                    $0.id != item.id &&
                    ($0.kind == "Prijava" || $0.kind == "Wi-Fi") &&
                    $0.password == item.password
                }
            let expiryAttention = item.kind == "Kartica" &&
                cardExpiryNeedsAttention(item.extraFields["Vrijedi do"] ?? "")
            let securityLabel: String = {
                if expiryAttention { return "Provjeri istek" }
                if item.kind == "Autentifikator", totpConfig != nil { return "TOTP aktivan" }
                if item.kind == "Autentifikator" { return "TOTP greška" }
                if isPasswordItem && item.password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Bez lozinke" }
                if duplicatedPassword { return "Ponovno korištena" }
                if isPasswordItem && isStrongPassword(item.password) { return "Snažna" }
                if isPasswordItem { return "Potrebno ažuriranje" }
                return "Zaštićena"
            }()
            let securityColor: Color = {
                switch securityLabel {
                case "Snažna", "Zaštićena", "TOTP aktivan": return good
                case "Ponovno korištena", "TOTP greška": return danger
                case "Potrebno ažuriranje", "Provjeri istek": return warn
                default: return muted
                }
            }()
            VStack(spacing: 0) {
                HStack(spacing: 10) {
                    Button { store.open(.vault) } label: {
                        Image(systemName: "chevron.left")
                            .font(.headline.bold())
                            .foregroundStyle(.white)
                            .frame(width: 40, height: 40)
                            .background(midnight.opacity(0.72))
                            .clipShape(Circle())
                    }
                    .buttonStyle(.plain)

                    Image(systemName: {
                        switch item.kind {
                        case "Bilješka": return "doc.text.fill"
                        case "Kartica": return "creditcard.fill"
                        case "Identitet": return "person.text.rectangle.fill"
                        case "Wi-Fi": return "wifi"
                        case "Autentifikator": return "shield.lefthalf.filled"
                        default: return "lock.fill"
                        }
                    }())
                    .foregroundStyle(cyan)
                    .frame(width: 50, height: 50)
                    .background(
                        LinearGradient(
                            colors: [cyan.opacity(0.18), indigo.opacity(0.13)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 16))

                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.title)
                            .font(.system(size: 28, weight: .black, design: .rounded))
                            .foregroundStyle(.white)
                            .lineLimit(2)
                            .minimumScaleFactor(0.72)
                        Text((item.kind + " • " + item.category).uppercased())
                            .font(.system(size: 10, weight: .semibold))
                            .tracking(0.7)
                            .foregroundStyle(muted)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                    Spacer()
                    Button {
                        store.toggleSelectedFavorite()
                    } label: {
                        Image(systemName: item.favorite ? "star.fill" : "star")
                            .foregroundStyle(item.favorite ? warn : ice)
                            .frame(width: 40, height: 40)
                            .background(item.favorite ? warn.opacity(0.12) : midnight.opacity(0.58))
                            .clipShape(Circle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel(item.favorite ? "Ukloni iz favorita" : "Dodaj u favorite")
                }
                .padding(.horizontal, 10)
                .padding(.vertical, 8)
                .background(
                    LinearGradient(
                        colors: [slate2.opacity(0.98), Color(hex: 0x101B2F).opacity(0.98)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .overlay(RoundedRectangle(cornerRadius: 24).stroke(cyan.opacity(0.22), lineWidth: 1))
                .clipShape(RoundedRectangle(cornerRadius: 24))
                .shadow(color: .black.opacity(0.18), radius: 7, y: 4)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)

                Picker("Prikaz", selection: $selectedTab) {
                    Text("Detalji").tag("Detalji")
                    Text("Sigurnost").tag("Sigurnost")
                    Text("Aktivnost").tag("Aktivnost")
                }
                .pickerStyle(.segmented)
                .tint(cyan)
                .padding(.horizontal, 18)
                .padding(.bottom, 6)

                ScrollView {
                    VStack(spacing: 10) {
                        if selectedTab == "Detalji" {
                        if item.kind == "Prijava" {
                            if !item.website.isEmpty {
                                DetailRow(icon: "link", title: "Web-stranica", value: item.website) {
                                    guard let url = normalizedWebURL(item.website) else {
                                        store.message = "Web-stranicu nije moguće otvoriti. Provjerite adresu."
                                        return
                                    }
                                    openURL(url) { accepted in
                                        if !accepted {
                                            store.message = "Web-stranicu nije moguće otvoriti."
                                        }
                                    }
                                }
                            }
                            if !item.username.isEmpty {
                                DetailRow(icon: "person", title: "Korisničko ime / e-pošta", value: item.username) {
                                    store.authorizeSensitive(reason: "Potvrdite identitet za kopiranje korisničkog imena.") {
                                        SecureClipboard.copy(item.username)
                                        store.message = "Korisničko ime kopirano je i automatski će se ukloniti."
                                    }
                                }
                            }
                        }

                        if item.kind == "Wi-Fi" {
                            if let network = item.extraFields["Naziv mreže"], !network.isEmpty {
                                DetailRow(icon: "wifi", title: "Naziv mreže", value: network)
                            }
                            if !item.username.isEmpty {
                                DetailRow(icon: "person", title: "Korisničko ime", value: item.username) {
                                    store.authorizeSensitive(reason: "Potvrdite identitet za kopiranje korisničkog imena.") {
                                        SecureClipboard.copy(item.username)
                                        store.message = "Korisničko ime kopirano je i automatski će se ukloniti."
                                    }
                                }
                            }
                            if let security = item.extraFields["Vrsta zaštite"], !security.isEmpty {
                                DetailRow(icon: "shield", title: "Vrsta zaštite", value: security)
                            }
                        }

                        if (item.kind == "Prijava" || item.kind == "Wi-Fi") && !item.password.isEmpty {
                            PasswordDetailRow(
                                password: item.password,
                                reveal: reveal,
                                onReveal: {
                                    if reveal {
                                        reveal = false
                                    } else {
                                        store.authorizeSensitive(reason: "Potvrdite identitet za prikaz lozinke.") {
                                            reveal = true
                                        }
                                    }
                                },
                                onCopy: {
                                    store.authorizeSensitive(reason: "Potvrdite identitet za kopiranje lozinke.") {
                                        SecureClipboard.copy(item.password)
                                        store.message = "Lozinka je kopirana i automatski će se ukloniti."
                                    }
                                }
                            )
                        }

                        if item.kind == "Kartica" {
                            if let holder = item.extraFields["Vlasnik kartice"], !holder.isEmpty {
                                DetailRow(icon: "person", title: "Vlasnik kartice", value: holder)
                            }
                            if let number = item.extraFields["Broj kartice"], !number.isEmpty {
                                SensitiveDetailView(
                                    icon: "creditcard",
                                    title: "Broj kartice",
                                    value: number,
                                    hidden: "•••• •••• •••• " + String(number.suffix(4)),
                                    reveal: revealCardNumber,
                                    onReveal: {
                                        if revealCardNumber {
                                            revealCardNumber = false
                                        } else {
                                            store.authorizeSensitive(reason: "Potvrdite identitet za prikaz broja kartice.") {
                                                revealCardNumber = true
                                            }
                                        }
                                    },
                                    onCopy: {
                                        store.authorizeSensitive(reason: "Potvrdite identitet za kopiranje broja kartice.") {
                                            SecureClipboard.copy(number)
                                            store.message = "Broj kartice kopiran je i automatski će se ukloniti."
                                        }
                                    }
                                )
                            }
                            if let expiry = item.extraFields["Vrijedi do"], !expiry.isEmpty {
                                DetailRow(icon: "calendar", title: "Vrijedi do", value: expiry)
                            }
                            if let code = item.extraFields["Sigurnosni kod"], !code.isEmpty {
                                SensitiveDetailView(
                                    icon: "lock",
                                    title: "Sigurnosni kod",
                                    value: code,
                                    hidden: "•••",
                                    reveal: revealSecurityCode,
                                    onReveal: {
                                        if revealSecurityCode {
                                            revealSecurityCode = false
                                        } else {
                                            store.authorizeSensitive(reason: "Potvrdite identitet za prikaz sigurnosnog koda.") {
                                                revealSecurityCode = true
                                            }
                                        }
                                    },
                                    onCopy: {
                                        store.authorizeSensitive(reason: "Potvrdite identitet za kopiranje sigurnosnog koda.") {
                                            SecureClipboard.copy(code)
                                            store.message = "Sigurnosni kod kopiran je i automatski će se ukloniti."
                                        }
                                    }
                                )
                            }
                        }

                        if item.kind == "Identitet" {
                            if let name = item.extraFields["Puno ime"], !name.isEmpty {
                                DetailRow(icon: "person", title: "Puno ime", value: name)
                            }
                            if let number = item.extraFields["Broj dokumenta"], !number.isEmpty {
                                SensitiveDetailView(
                                    icon: "person.text.rectangle",
                                    title: "Broj dokumenta",
                                    value: number,
                                    hidden: "••••" + String(number.suffix(4)),
                                    reveal: revealDocumentNumber,
                                    onReveal: {
                                        if revealDocumentNumber {
                                            revealDocumentNumber = false
                                        } else {
                                            store.authorizeSensitive(reason: "Potvrdite identitet za prikaz broja dokumenta.") {
                                                revealDocumentNumber = true
                                            }
                                        }
                                    },
                                    onCopy: {
                                        store.authorizeSensitive(reason: "Potvrdite identitet za kopiranje broja dokumenta.") {
                                            SecureClipboard.copy(number)
                                            store.message = "Broj dokumenta kopiran je i automatski će se ukloniti."
                                        }
                                    }
                                )
                            }
                            if let expiry = item.extraFields["Datum isteka"], !expiry.isEmpty {
                                DetailRow(icon: "calendar", title: "Datum isteka", value: expiry)
                            }
                        }

                        if item.kind == "Autentifikator" {
                            if let config = totpConfig {
                                TimelineView(.periodic(from: .now, by: 1)) { context in
                                    TotpCodeCard(config: config, date: context.date) {
                                        if let code = generateTotp(config, at: context.date) {
                                            store.authorizeSensitive(reason: "Potvrdite identitet za kopiranje 2FA koda.") {
                                                SecureClipboard.copy(code)
                                                store.message = "2FA kod kopiran je i automatski će se ukloniti."
                                            }
                                        }
                                    }
                                }

                                if !config.issuer.isEmpty {
                                    DetailRow(icon: "building.2", title: "Izdavatelj", value: config.issuer)
                                }
                                if !config.account.isEmpty {
                                    DetailRow(icon: "person", title: "Račun", value: config.account)
                                }

                                SensitiveDetailView(
                                    icon: "key.fill",
                                    title: "TOTP tajna",
                                    value: config.secret,
                                    hidden: "••••••••" + String(config.secret.suffix(4)),
                                    reveal: revealTotpSecret,
                                    onReveal: {
                                        if revealTotpSecret {
                                            revealTotpSecret = false
                                        } else {
                                            store.authorizeSensitive(reason: "Potvrdite identitet za prikaz TOTP tajne.") {
                                                revealTotpSecret = true
                                            }
                                        }
                                    },
                                    onCopy: {
                                        store.authorizeSensitive(reason: "Potvrdite identitet za kopiranje TOTP tajne.") {
                                            SecureClipboard.copy(config.secret)
                                            store.message = "TOTP tajna kopirana je i automatski će se ukloniti."
                                        }
                                    }
                                )

                                DetailMetaCard(
                                    icon: "clock.arrow.circlepath",
                                    title: "TOTP postavke",
                                    value: "\(config.algorithm) • \(config.digits) znamenki • \(config.period) s",
                                    accent: good
                                )
                            } else {
                                GlassCard {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .font(.title2)
                                        .foregroundStyle(danger)
                                    Text("TOTP konfiguracija nije valjana.")
                                        .font(.headline)
                                        .foregroundStyle(.white)
                                    Text("Uredite stavku i ponovno unesite Base32 tajnu ili otpauth URI.")
                                        .foregroundStyle(muted)
                                    Button {
                                        store.editSelected()
                                    } label: {
                                        Text("Uredi autentifikator")
                                            .fontWeight(.bold)
                                            .frame(maxWidth: .infinity)
                                            .padding(.vertical, 11)
                                    }
                                    .buttonStyle(.plain)
                                    .foregroundStyle(midnight)
                                    .background(cyan)
                                    .clipShape(Capsule())
                                }
                            }
                        }

                        if !item.notes.isEmpty {
                            DetailRow(icon: "doc.text", title: "Bilješke", value: item.notes)
                        }

                        ViewThatFits(in: .horizontal) {
                            HStack(spacing: 10) {
                                DetailMetaCard(
                                    icon: "shield.fill",
                                    title: "Ocjena sigurnosti",
                                    value: securityLabel,
                                    accent: securityColor
                                )
                                DetailMetaCard(
                                    icon: "clock.fill",
                                    title: "Zadnje ažurirano",
                                    value: item.updatedAt.formatted(date: .abbreviated, time: .omitted),
                                    accent: indigo
                                )
                            }
                            VStack(spacing: 10) {
                                DetailMetaCard(
                                    icon: "shield.fill",
                                    title: "Ocjena sigurnosti",
                                    value: securityLabel,
                                    accent: securityColor
                                )
                                DetailMetaCard(
                                    icon: "clock.fill",
                                    title: "Zadnje ažurirano",
                                    value: item.updatedAt.formatted(date: .abbreviated, time: .omitted),
                                    accent: indigo
                                )
                            }
                        }

                        ViewThatFits(in: .horizontal) {
                            HStack(spacing: 10) {
                                detailEditButton
                                detailDeleteButton
                            }
                            VStack(spacing: 8) {
                                detailEditButton
                                detailDeleteButton
                            }
                        }
                        }

                        if selectedTab == "Sigurnost" {
                            GlassCard {
                                Image(systemName: "shield.fill")
                                    .font(.title2)
                                    .foregroundStyle(securityColor)
                                Text("Ocjena sigurnosti")
                                    .font(.caption)
                                    .foregroundStyle(muted)
                                Text(securityLabel)
                                    .font(.title2.bold())
                                    .foregroundStyle(securityColor)
                                Text({
                                    if expiryAttention {
                                        return "Datum isteka kartice je prošao ili je neispravan. Provjerite karticu i ažurirajte podatke."
                                    }
                                    if duplicatedPassword {
                                        return "Ova se lozinka koristi i na drugoj stavci. Preporučujemo jedinstvenu lozinku."
                                    }
                                    if isPasswordItem && item.password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                        return "Ova stavka nema spremljenu lozinku."
                                    }
                                    if isPasswordItem && !isStrongPassword(item.password) {
                                        return "Lozinka je prekratka, predvidljiva ili nema dovoljno različitih vrsta znakova."
                                    }
                                    if isPasswordItem {
                                        return "Lozinka zadovoljava preporučene sigurnosne uvjete."
                                    }
                                    if item.kind == "Autentifikator", totpConfig != nil {
                                        return "Kod se automatski osvježava prema vremenu uređaja."
                                    }
                                    if item.kind == "Autentifikator" {
                                        return "TOTP konfiguracija nije valjana i treba je urediti."
                                    }
                                    return "Ova vrsta stavke nema lozinku za procjenu, ali je sadržaj zaštićen trezorom."
                                }())
                                .foregroundStyle(muted)
                            }

                            DetailMetaCard(
                                icon: "lock.shield.fill",
                                title: "Zaštita stavke",
                                value: store.sensitiveReauthEnabled && store.biometricEnabled
                                    ? "Dodatna potvrda uključena"
                                    : "Zaštita trezora",
                                accent: cyan
                            )

                            if isPasswordItem && (item.password.isEmpty || duplicatedPassword || !isStrongPassword(item.password)) {
                                Button {
                                    store.editSelected()
                                } label: {
                                    Label("Uredi i promijeni lozinku", systemImage: "pencil")
                                        .fontWeight(.bold)
                                        .frame(maxWidth: .infinity)
                                        .frame(height: 54)
                                }
                                .buttonStyle(.plain)
                                .foregroundStyle(midnight)
                                .background(cyan)
                                .clipShape(Capsule())
                            }
                        }

                        if selectedTab == "Aktivnost" {
                            DetailMetaCard(
                                icon: "clock.fill",
                                title: "Zadnja izmjena",
                                value: item.updatedAt.formatted(date: .abbreviated, time: .shortened),
                                accent: indigo
                            )

                            GlassCard {
                                Image(systemName: "info.circle.fill")
                                    .font(.title2)
                                    .foregroundStyle(cyan)
                                Text("Aktivnost stavke")
                                    .font(.headline)
                                    .foregroundStyle(.white)
                                Text(
                                    "Keyra čuva samo vrijeme posljednje izmjene ove stavke. Radi privatnosti ne zapisuje povijest otvaranja, prikaza ni kopiranja osjetljivih vrijednosti."
                                )
                                .foregroundStyle(muted)
                            }
                        }
                    }
                    .padding(18)
                }
            }
            .confirmationDialog(
                "Izbrisati stavku?",
                isPresented: $confirmDelete,
                titleVisibility: .visible
            ) {
                Button("Izbriši", role: .destructive) {
                    store.authorizeSensitive(reason: "Potvrdite identitet za brisanje stavke.") {
                        store.deleteSelected()
                    }
                }
                Button("Odustani", role: .cancel) {}
            } message: {
                Text("Ova radnja ne može se poništiti.")
            }
            .onChange(of: item.id) { _, _ in
                selectedTab = "Detalji"
                reveal = false
                revealCardNumber = false
                revealSecurityCode = false
                revealDocumentNumber = false
                revealTotpSecret = false
            }
        }
    }

    private var detailEditButton: some View {
        Button {
            store.editSelected()
        } label: {
            Label("Uredi stavku", systemImage: "pencil")
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
        }
        .buttonStyle(.plain)
        .foregroundStyle(ice)
        .overlay(Capsule().stroke(ice.opacity(0.5), lineWidth: 1))
    }

    private var detailDeleteButton: some View {
        Button {
            confirmDelete = true
        } label: {
            Label("Izbriši", systemImage: "trash")
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
        }
        .buttonStyle(.plain)
        .foregroundStyle(danger)
        .overlay(Capsule().stroke(danger.opacity(0.6), lineWidth: 1))
    }
}

struct TotpCodeCard: View {
    let config: TotpConfig
    let date: Date
    let onCopy: () -> Void

    var body: some View {
        let code = generateTotp(config, at: date) ?? String(repeating: "—", count: config.digits)
        let remaining = totpRemainingSeconds(config, at: date)
        let progress = Double(remaining) / Double(config.period)

        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.title2)
                    .foregroundStyle(good)
                    .frame(width: 48, height: 48)
                    .background(good.opacity(0.14))
                    .clipShape(RoundedRectangle(cornerRadius: 14))

                VStack(alignment: .leading, spacing: 2) {
                    Text("Vremenski 2FA kod")
                        .font(.headline)
                        .foregroundStyle(.white)
                    Text("Automatski se mijenja svakih \(config.period) s")
                        .font(.caption)
                        .foregroundStyle(muted)
                }

                Spacer()

                Button(action: onCopy) {
                    Image(systemName: "doc.on.doc")
                        .foregroundStyle(ice)
                        .frame(width: 42, height: 42)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Kopiraj 2FA kod")
            }

            Text(formatTotpCode(code))
                .font(.system(size: 38, weight: .black, design: .rounded))
                .tracking(2)
                .foregroundStyle(cyan)
                .minimumScaleFactor(0.72)

            ProgressView(value: progress, total: 1)
                .tint(good)

            Text("\(remaining) s do novog koda")
                .font(.caption)
                .foregroundStyle(muted)

            Text("Ako kod ne radi, provjerite jesu li datum i vrijeme uređaja točni.")
                .font(.caption)
                .foregroundStyle(muted)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 24).stroke(good.opacity(0.65), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 24))
    }
}

struct DetailMetaCard: View {
    let icon: String
    let title: String
    let value: String
    let accent: Color

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(accent)
                .frame(width: 42, height: 42)
                .background(accent.opacity(0.14))
                .clipShape(RoundedRectangle(cornerRadius: 13))

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(muted)
                Text(value)
                    .fontWeight(.bold)
                    .foregroundStyle(title == "Ocjena sigurnosti" ? accent : .white)
                    .lineLimit(2)
                    .minimumScaleFactor(0.8)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(accent.opacity(0.45), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }
}

struct SensitiveDetailView: View {
    let icon: String
    let title: String
    let value: String
    let hidden: String
    let reveal: Bool
    let onReveal: () -> Void
    let onCopy: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .foregroundStyle(cyan)
                .frame(width: 48, height: 48)
                .background(Color(hex: 0x063A3A))
                .clipShape(RoundedRectangle(cornerRadius: 14))

            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.caption).foregroundStyle(muted)
                Text(reveal ? value : hidden).foregroundStyle(.white)
            }

            Spacer()

            Button(action: onReveal) {
                Image(systemName: reveal ? "eye.slash" : "eye").foregroundStyle(ice)
            }
            .buttonStyle(.plain)

            Button(action: onCopy) {
                Image(systemName: "doc.on.doc").foregroundStyle(cyan)
            }
            .buttonStyle(.plain)
        }
        .padding(16)
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(ice.opacity(0.18), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }
}

struct PasswordDetailRow: View {
    let password: String
    let reveal: Bool
    let onReveal: () -> Void
    let onCopy: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.fill")
                .foregroundStyle(cyan)
                .frame(width: 48, height: 48)
                .background(Color(hex: 0x063A3A))
                .clipShape(RoundedRectangle(cornerRadius: 14))

            VStack(alignment: .leading, spacing: 3) {
                Text("Lozinka").font(.caption).foregroundStyle(muted)
                Text(reveal ? password : "••••••••••••••")
                    .foregroundStyle(.white)
            }

            Spacer()

            Button(action: onReveal) {
                Image(systemName: reveal ? "eye.slash" : "eye")
                    .foregroundStyle(ice)
            }
            .buttonStyle(.plain)

            Button(action: onCopy) {
                Image(systemName: "doc.on.doc")
                    .foregroundStyle(cyan)
            }
            .buttonStyle(.plain)
        }
        .padding(16)
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(ice.opacity(0.18), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }
}

struct DetailRow: View {
    let icon: String
    let title: String
    let value: String
    var action: (() -> Void)?

    var body: some View {
        Button {
            action?()
        } label: {
            HStack(spacing: 12) {
                Image(systemName: icon)
                    .foregroundStyle(cyan)
                    .frame(width: 48, height: 48)
                    .background(Color(hex: 0x0B3551))
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                VStack(alignment: .leading, spacing: 3) {
                    Text(title).font(.caption).foregroundStyle(muted)
                    Text(value).foregroundStyle(.white).multilineTextAlignment(.leading)
                }
                Spacer()
                if action != nil { Image(systemName: "chevron.right").foregroundStyle(ice) }
            }
            .padding(16)
            .background(slate)
            .overlay(RoundedRectangle(cornerRadius: 20).stroke(ice.opacity(0.18), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 20))
        }
        .buttonStyle(.plain)
        .disabled(action == nil)
    }
}

struct SettingsView: View {
    @EnvironmentObject var store: KeyraStore
    @Environment(\.openURL) private var openURL
    @State private var confirmErase = false
    @State private var backupDocument = KeyraBackupDocument()
    @State private var exportBackupFile = false
    @State private var importBackupFile = false
    @State private var pendingImportPayload: String?
    @State private var recoveryDocument = KeyraBackupDocument()
    @State private var exportRecoveryFile = false
    @State private var importRecoveryFile = false
    @State private var showRecoveryExportPrompt = false
    @State private var recoveryExportPassphrase = ""
    @State private var recoveryExportConfirm = ""
    @State private var pendingRecoveryImportPayload: String?
    @State private var recoveryImportPassphrase = ""

    private func runProtectedFileImport(_ payload: String) {
        store.authorizeCritical(reason: "Potvrdite identitet za uvoz sigurnosne kopije.") {
            _ = store.importBackupPayload(payload)
        }
    }

    private func prepareBackupExport() {
        store.authorizeCritical(reason: "Potvrdite identitet za izradu sigurnosne kopije.") {
            guard let payload = store.makeBackupPayload() else { return }
            backupDocument = KeyraBackupDocument(payload: payload)
            exportBackupFile = true
        }
    }

    private func prepareRecoveryExport() {
        let passphrase = recoveryExportPassphrase
        guard isStrongRecoveryPassphrase(passphrase), passphrase == recoveryExportConfirm else {
            store.message = "Recovery lozinka nije dovoljno jaka ili se potvrda ne podudara."
            return
        }

        store.authorizeCritical(reason: "Potvrdite identitet za izvoz Recovery Key datoteke.") {
            defer {
                recoveryExportPassphrase = ""
                recoveryExportConfirm = ""
            }
            guard let payload = store.makeRecoveryKeyPayload(passphrase: passphrase) else { return }
            recoveryDocument = KeyraBackupDocument(payload: payload)
            exportRecoveryFile = true
        }
    }

    private func runProtectedRecoveryImport(_ payload: String) {
        let passphrase = recoveryImportPassphrase
        recoveryImportPassphrase = ""
        store.authorizeCritical(reason: "Potvrdite identitet za uvoz Recovery Key datoteke.") {
            _ = store.importRecoveryKeyPayload(payload, passphrase: passphrase)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "POSTAVKE")

            ScrollView {
                VStack(spacing: 10) {
                    SettingsIntroCard(
                        title: "Vaša Keyra, vaše postavke.",
                        subtitle: "Sve važne opcije na jednom mjestu."
                    )

                    SectionLabel("ZAŠTITA")

                    SettingRow(
                        icon: "faceid",
                        title: "Biometrijsko otključavanje",
                        subtitle: "Brže otključajte trezor biometrijom ili zaključavanjem uređaja."
                    ) {
                        Toggle(
                            "",
                            isOn: Binding(
                                get: { store.biometricEnabled },
                                set: { store.toggleBiometric($0) }
                            )
                        )
                        .labelsHidden()
                        .tint(cyan)
                    }

                    SettingRow(
                        icon: "eye.fill",
                        title: "Potvrda za osjetljive podatke",
                        subtitle: "Zatražite dodatnu potvrdu prije prikaza ili kopiranja tajni."
                    ) {
                        Toggle(
                            "",
                            isOn: Binding(
                                get: { store.sensitiveReauthEnabled },
                                set: { store.toggleSensitiveReauth($0) }
                            )
                        )
                        .labelsHidden()
                        .tint(cyan)
                        .disabled(!store.biometricEnabled)
                    }

                    SettingRow(
                        icon: "timer",
                        title: "Automatsko zaključavanje",
                        subtitle: "Odredite kada se trezor zaključava nakon napuštanja aplikacije."
                    ) {
                        Button {
                            store.cycleAutoLock()
                        } label: {
                            Text(store.autoLockLabel)
                                .foregroundStyle(cyan)
                                .font(.subheadline.weight(.semibold))
                        }
                        .buttonStyle(.plain)
                    }

                    Button {
                        store.open(.security)
                    } label: {
                        SettingRow(
                            icon: "shield.checkered",
                            title: "Provjera sigurnosti",
                            subtitle: "Pregledajte slabe i ponovljene lozinke."
                        ) {
                            Image(systemName: "chevron.right").foregroundStyle(ice)
                        }
                    }
                    .buttonStyle(.plain)

                    SectionLabel("SIGURNOSNE KOPIJE")

                    SettingRow(
                        icon: "externaldrive.badge.plus",
                        title: "Spremi sigurnosnu kopiju",
                        subtitle: "Spremite šifriranu .keyra datoteku u Files ili odabrani cloud provider."
                    ) {
                        Button {
                            prepareBackupExport()
                        } label: {
                            Image(systemName: "square.and.arrow.up").foregroundStyle(cyan)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Spremi sigurnosnu kopiju")
                    }

                    SettingRow(
                        icon: "externaldrive.badge.checkmark",
                        title: "Vrati sigurnosnu kopiju",
                        subtitle: "Odaberite .keyra datoteku i vratite trezor tek nakon potvrde."
                    ) {
                        Button {
                            importBackupFile = true
                        } label: {
                            Image(systemName: "folder").foregroundStyle(cyan)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Vrati sigurnosnu kopiju")
                    }

                    SettingsHintCard(
                        icon: "checkmark.icloud.fill",
                        text: "Keyra šifrira backup prije spremanja. Nema Keyra računa ni vlastitog cloud trezora."
                    )

                    SectionLabel("OPORAVAK")

                    SettingRow(
                        icon: "key.fill",
                        title: "Izvezi Recovery Key",
                        subtitle: "Spremite ključ za obnovu na sigurno mjesto."
                    ) {
                        Button {
                            recoveryExportPassphrase = ""
                            recoveryExportConfirm = ""
                            showRecoveryExportPrompt = true
                        } label: {
                            Image(systemName: "square.and.arrow.up").foregroundStyle(cyan)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Izvezi Recovery Key")
                    }

                    SettingRow(
                        icon: "key.fill",
                        title: "Uvezi Recovery Key",
                        subtitle: "Provjerite ključ za obnovu i potvrdite novu zaštitu trezora."
                    ) {
                        Button {
                            importRecoveryFile = true
                        } label: {
                            Image(systemName: "folder").foregroundStyle(cyan)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Uvezi Recovery Key")
                    }

                    SectionLabel("PRIVATNOST I APLIKACIJA")

                    Button {
                        if let url = URL(string: "https://app.brendigo.com/keya/politika-privatnosti") {
                            openURL(url)
                        }
                    } label: {
                        SettingRow(
                            icon: "hand.raised.fill",
                            title: "Pravila privatnosti",
                            subtitle: "Pročitajte pravila privatnosti."
                        ) {
                            Image(systemName: "arrow.up.right").foregroundStyle(ice)
                        }
                    }
                    .buttonStyle(.plain)

                    Button {
                        if let url = URL(string: "https://app.brendigo.com/keya/uvjeti-koristenja") {
                            openURL(url)
                        }
                    } label: {
                        SettingRow(
                            icon: "doc.text",
                            title: "Uvjeti korištenja",
                            subtitle: "Pročitajte uvjete korištenja aplikacije."
                        ) {
                            Image(systemName: "arrow.up.right").foregroundStyle(ice)
                        }
                    }
                    .buttonStyle(.plain)

                    Button {
                        if let url = URL(string: "https://app.brendigo.com/keya/o-nama") {
                            openURL(url)
                        }
                    } label: {
                        SettingRow(
                            icon: "info.circle",
                            title: "O aplikaciji",
                            subtitle: "Keyra \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—")"
                        ) {
                            Image(systemName: "arrow.up.right").foregroundStyle(ice)
                        }
                    }
                    .buttonStyle(.plain)

                    Button {
                        confirmErase = true
                    } label: {
                        SettingRow(
                            icon: "trash.slash.fill",
                            title: "Izbriši sve podatke",
                            subtitle: "Trajno izbrišite trezor i postavke s ovog uređaja."
                        ) {
                            Image(systemName: "chevron.right").foregroundStyle(danger)
                        }
                    }
                    .buttonStyle(.plain)

                    Button {
                        store.lock()
                    } label: {
                        Label("Zaključaj trezor", systemImage: "lock.fill")
                            .font(.subheadline.weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(slate2)
                            .overlay(RoundedRectangle(cornerRadius: 18).stroke(ice.opacity(0.28), lineWidth: 1))
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.white)
                }
                .padding(18)
                .padding(.bottom, 100)
            }
        }
        .confirmationDialog(
            "Izbrisati sve podatke?",
            isPresented: $confirmErase,
            titleVisibility: .visible
        ) {
            Button("Trajno izbriši", role: .destructive) {
                store.authorizeCritical(reason: "Potvrdite brisanje podataka.") {
                    _ = store.eraseAllLocalData()
                }
            }
            Button("Odustani", role: .cancel) {}
        } message: {
            Text(
                "Trezor, glavna lozinka i postavke bit će trajno izbrisani s ovog uređaja. " +
                "Ova radnja ne briše .keyra kopije koje ste sami spremili u Files ili cloud."
            )
        }
        .alert("Izvezi Recovery Key", isPresented: $showRecoveryExportPrompt) {
            SecureField("Recovery lozinka", text: $recoveryExportPassphrase)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            SecureField("Ponovite recovery lozinku", text: $recoveryExportConfirm)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Izvezi") {
                prepareRecoveryExport()
            }
            .disabled(
                !isStrongRecoveryPassphrase(recoveryExportPassphrase) ||
                recoveryExportPassphrase != recoveryExportConfirm
            )
            Button("Odustani", role: .cancel) {
                recoveryExportPassphrase = ""
                recoveryExportConfirm = ""
            }
        } message: {
            Text(
                "Ključ za obnovu i njegovu lozinku čuvajte na dva odvojena mjesta. " +
                "Koristite najmanje 16 znakova i dovoljnu složenost ili najmanje četiri riječi; datoteku i lozinku čuvajte odvojeno."
            )
        }
        .alert(
            "Uvezi Recovery Key",
            isPresented: Binding(
                get: { pendingRecoveryImportPayload != nil },
                set: {
                    if !$0 {
                        pendingRecoveryImportPayload = nil
                        recoveryImportPassphrase = ""
                    }
                }
            )
        ) {
            SecureField("Recovery lozinka", text: $recoveryImportPassphrase)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Verificiraj i uvezi") {
                if let payload = pendingRecoveryImportPayload {
                    pendingRecoveryImportPayload = nil
                    runProtectedRecoveryImport(payload)
                }
            }
            .disabled(recoveryImportPassphrase.isEmpty)
            Button("Odustani", role: .cancel) {
                pendingRecoveryImportPayload = nil
                recoveryImportPassphrase = ""
            }
        } message: {
            Text(
                "Keyra prvo verificira recovery datoteku i postojeći trezor. " +
                "Recovery Key ne vraća izbrisane zapise samostalno; za to koristite zasebnu šifriranu KEYRA2 sigurnosnu kopiju."
            )
        }
        .fileExporter(
            isPresented: $exportRecoveryFile,
            document: recoveryDocument,
            contentType: UTType(filenameExtension: "keyra") ?? .data,
            defaultFilename: "Keyra-Recovery"
        ) { result in
            switch result {
            case .success:
                store.message = "Šifrirani Recovery Key spremljen je na odabrano mjesto."
            case .failure:
                store.message = "Recovery Key nije moguće spremiti na odabrano mjesto."
            }
        }
        .fileImporter(
            isPresented: $importRecoveryFile,
            allowedContentTypes: KeyraBackupDocument.readableContentTypes,
            allowsMultipleSelection: false
        ) { result in
            do {
                let urls = try result.get()
                guard let url = urls.first else { return }
                let accessed = url.startAccessingSecurityScopedResource()
                defer {
                    if accessed { url.stopAccessingSecurityScopedResource() }
                }
                let payload = try readLimitedKeyraText(url, maxBytes: 16_384)
                if payload.isEmpty {
                    store.message = "Recovery Key datoteka nije valjana ili je prevelika."
                    return
                }
                recoveryImportPassphrase = ""
                pendingRecoveryImportPayload = payload
            } catch {
                store.message = "Recovery Key datoteku nije moguće otvoriti."
            }
        }
        .fileExporter(
            isPresented: $exportBackupFile,
            document: backupDocument,
            contentType: UTType(filenameExtension: "keyra") ?? .data,
            defaultFilename: "Keyra-backup"
        ) { result in
            switch result {
            case .success:
                store.message = "Šifrirana .keyra kopija spremljena je na odabrano mjesto."
            case .failure:
                store.message = "Sigurnosnu kopiju nije moguće spremiti na odabrano mjesto."
            }
        }
        .fileImporter(
            isPresented: $importBackupFile,
            allowedContentTypes: KeyraBackupDocument.readableContentTypes,
            allowsMultipleSelection: false
        ) { result in
            do {
                let urls = try result.get()
                guard let url = urls.first else { return }
                let accessed = url.startAccessingSecurityScopedResource()
                defer {
                    if accessed { url.stopAccessingSecurityScopedResource() }
                }
                let payload = try readLimitedKeyraText(url, maxBytes: 2_500_000)
                if payload.isEmpty {
                    store.message = "Odabrana sigurnosna kopija nije valjana ili je prevelika."
                    return
                }
                pendingImportPayload = payload
            } catch {
                store.message = "Odabranu sigurnosnu kopiju nije moguće otvoriti."
            }
        }
        .confirmationDialog(
            "Uvesti šifriranu datoteku?",
            isPresented: Binding(
                get: { pendingImportPayload != nil },
                set: { if !$0 { pendingImportPayload = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Uvezi i zamijeni", role: .destructive) {
                if let payload = pendingImportPayload {
                    pendingImportPayload = nil
                    runProtectedFileImport(payload)
                }
            }
            Button("Odustani", role: .cancel) {
                pendingImportPayload = nil
            }
        } message: {
            Text(
                "Odabrana .keyra kopija zamijenit će trenutačni sadržaj trezora. " +
                "Datoteka se prvo provjerava i dešifrira prije spremanja."
            )
        }
    }
}

struct SecurityCenterView: View {
    @EnvironmentObject var store: KeyraStore

    private var duplicateIDs: Set<UUID> {
        let passwordItems = store.items.filter { ($0.kind == "Prijava" || $0.kind == "Wi-Fi") && !$0.password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        let groups = Dictionary(grouping: passwordItems, by: { $0.password })
        return Set(groups.values.filter { $0.count > 1 }.flatMap { $0.map(\.id) })
    }

    private var weakItems: [VaultItem] {
        store.items.filter { ($0.kind == "Prijava" || $0.kind == "Wi-Fi") && !isStrongPassword($0.password) }
    }

    private var strongItems: [VaultItem] {
        store.items.filter { ($0.kind == "Prijava" || $0.kind == "Wi-Fi") && isStrongPassword($0.password) && !duplicateIDs.contains($0.id) }
    }

    private var invalidTotpItems: [VaultItem] {
        store.items.filter { $0.kind == "Autentifikator" && totpConfigFromFields($0.extraFields) == nil }
    }

    private var expiredCardItems: [VaultItem] {
        let ids = expiredCardIssueIDs(store.items)
        return store.items.filter { ids.contains($0.id) }
    }

    private var score: Int? {
        securityScore(store.items)
    }

    private var issues: [VaultItem] {
        Array(Dictionary(uniqueKeysWithValues:
            (weakItems + store.items.filter { duplicateIDs.contains($0.id) } + invalidTotpItems + expiredCardItems).map { ($0.id, $0) }
        ).values)
        .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "SIGURNOST")
            ScrollView {
                VStack(spacing: 12) {
                    GlassCard {
                        Text("Ocjena lozinki")
                            .foregroundStyle(muted)
                        HStack(alignment: .lastTextBaseline, spacing: 2) {
                            Text(score.map(String.init) ?? "—")
                                .font(.system(size: 54, weight: .black))
                                .foregroundStyle(score == nil ? muted : (score == 100 ? good : warn))
                            Text("/100")
                                .font(.headline)
                                .foregroundStyle(muted)
                        }
                        ProgressView(value: Double(score ?? 0), total: 100)
                            .tint(score == nil ? muted : (score == 100 ? good : warn))
                        Text({
                            guard let score else {
                                return issues.isEmpty
                                    ? "Dodajte barem jednu lozinku kako bi Keyra mogla izračunati ocjenu."
                                    : "Nema lozinki za ocjenu. Provjerite upozorenja za 2FA i kartice."
                            }
                            return issues.isEmpty
                                ? "Nisu pronađeni sigurnosni problemi."
                                : "Pregledajte stavke koje zahtijevaju pažnju."
                        }())
                        .foregroundStyle(muted)
                    }

                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: 10) {
                            Summary(value: "\(strongItems.count)", label: "Snažne", accent: good)
                            Summary(value: "\(issues.count)", label: "Rizične", accent: warn)
                            Summary(value: "\(duplicateIDs.count)", label: "Ponovljene", accent: danger)
                        }

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                Summary(value: "\(strongItems.count)", label: "Snažne", accent: good)
                                    .frame(width: 110)
                                Summary(value: "\(issues.count)", label: "Rizične", accent: warn)
                                    .frame(width: 110)
                                Summary(value: "\(duplicateIDs.count)", label: "Ponovljene", accent: danger)
                                    .frame(width: 124)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        SectionLabel("AKTIVNE ZAŠTITE")
                        GlassCard {
                            SecurityProtectionRow(
                                icon: "lock.shield.fill",
                                title: "Šifrirani trezor",
                                subtitle: "Zaštićeni podaci"
                            )
                            Divider().overlay(ice.opacity(0.14))
                            SecurityProtectionRow(
                                icon: "eye.slash.fill",
                                title: "Zaštita zaslona",
                                subtitle: "Sadržaj se skriva pri neaktivnoj aplikaciji i tijekom aktivnog snimanja zaslona."
                            )
                            Divider().overlay(ice.opacity(0.14))
                            SecurityProtectionRow(
                                icon: "doc.on.doc.fill",
                                title: "Privremeni međuspremnik",
                                subtitle: "Osjetljivi sadržaj uklanja se nakon 30 sekundi."
                            )
                            Divider().overlay(ice.opacity(0.14))
                            SecurityProtectionRow(
                                icon: "checkmark.shield.fill",
                                title: "Kritične radnje",
                                subtitle: "Backup, Recovery Key i brisanje traže potvrdu vlasnika uređaja kada je dostupna."
                            )
                        }

                        SectionLabel("STAVKE KOJE ZAHTIJEVAJU PAŽNJU")
                        ForEach(issues) { item in
                            Button {
                                store.select(item)
                            } label: {
                                HStack(spacing: 12) {
                                    Image(systemName: duplicateIDs.contains(item.id) ? "doc.on.doc" : "exclamationmark.triangle")
                                        .foregroundStyle(duplicateIDs.contains(item.id) ? danger : warn)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(item.title).fontWeight(.bold).foregroundStyle(.white)
                                        Text({
                                            let duplicate = duplicateIDs.contains(item.id)
                                            let weak = !isStrongPassword(item.password)
                                            if item.kind == "Kartica" {
                                                return "Datum isteka kartice je prošao ili je neispravan. Uredite karticu."
                                            }
                                            if item.kind == "Autentifikator" {
                                                return "Neispravna 2FA tajna ili postavke. Uredite autentifikator."
                                            }
                                            if item.password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                                return "Ovoj stavci nedostaje spremljena lozinka."
                                            }
                                            if duplicate && weak {
                                                return "Lozinka je slaba i koristi se na više mjesta."
                                            }
                                            if duplicate {
                                                return "Lozinka se koristi na više mjesta."
                                            }
                                            return "Lozinka nije dovoljno snažna i preporučuje se zamjena."
                                        }())
                                        .font(.subheadline)
                                        .foregroundStyle(muted)
                                    }
                                    Spacer()
                                    Image(systemName: "chevron.right").foregroundStyle(ice)
                                }
                                .padding(14)
                                .background(slate)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 20)
                                        .stroke((duplicateIDs.contains(item.id) ? danger : warn).opacity(0.55), lineWidth: 1)
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 20))
                            }
                            .buttonStyle(.plain)
                        }

                        if issues.isEmpty {
                            HStack(spacing: 12) {
                                Image(systemName: score == nil ? "info.circle.fill" : "checkmark.shield.fill")
                                    .foregroundStyle(score == nil ? ice : good)
                                Text(score == nil ? "Nema prijava ni Wi-Fi stavki za provjeru." : "Nisu pronađene rizične ni ponovljene lozinke.")
                                    .foregroundStyle(.white)
                                Spacer()
                            }
                            .padding(18)
                            .background((score == nil ? ice : good).opacity(0.10))
                            .overlay(RoundedRectangle(cornerRadius: 20).stroke((score == nil ? ice : good).opacity(0.55), lineWidth: 1))
                            .clipShape(RoundedRectangle(cornerRadius: 20))
                        }
                    }
                }
                .padding(18)
                .padding(.bottom, 100)
            }
        }
    }
}

struct SecurityProtectionRow: View {
    let icon: String
    let title: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(good)
                .frame(width: 38, height: 38)
                .background(
                    LinearGradient(
                        colors: [cyan.opacity(0.16), indigo.opacity(0.12)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .clipShape(RoundedRectangle(cornerRadius: 12))

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.white)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(muted)
            }

            Spacer()

            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(good)
        }
        .padding(.vertical, 2)
    }
}

struct SectionLabel: View {
    let value: String
    init(_ value: String) { self.value = value }

    var body: some View {
        HStack(spacing: 8) {
            RoundedRectangle(cornerRadius: 2)
                .fill(
                    LinearGradient(
                        colors: [cyan, indigo],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .frame(width: 4, height: 18)
            Text(value.uppercased())
                .font(.system(size: 11, weight: .bold))
                .tracking(1.7)
                .foregroundStyle(ice)
        }
        .padding(.top, 10)
        .padding(.bottom, 2)
    }
}

struct SettingsIntroCard: View {
    let title: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "slider.horizontal.3")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(cyan)
                .frame(width: 46, height: 46)
                .background(
                    LinearGradient(
                        colors: [cyan.opacity(0.18), indigo.opacity(0.14)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .clipShape(RoundedRectangle(cornerRadius: 15))

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.headline)
                    .foregroundStyle(.white)
                Text(subtitle)
                    .font(.subheadline)
                    .foregroundStyle(muted)
            }

            Spacer()
        }
        .padding(16)
        .background(slate2.opacity(0.96))
        .overlay(RoundedRectangle(cornerRadius: 24).stroke(cyan.opacity(0.24), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 24))
        .shadow(color: .black.opacity(0.14), radius: 5, y: 2)
    }
}

struct SettingsHintCard: View {
    let icon: String
    let text: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(good)
            Text(text)
                .font(.caption)
                .foregroundStyle(muted)
            Spacer()
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
        .background(good.opacity(0.07))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(good.opacity(0.22), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 18))
    }
}

struct SettingRow<Trailing: View>: View {
    let icon: String
    let title: String
    let subtitle: String
    @ViewBuilder let trailing: Trailing

    init(icon: String, title: String, subtitle: String, @ViewBuilder trailing: () -> Trailing) {
        self.icon = icon
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing()
    }

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: 12) {
                settingIcon
                settingText
                Spacer(minLength: 8)
                trailing
            }

            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    settingIcon
                    settingText
                }
                HStack {
                    Spacer()
                    trailing
                }
            }
        }
        .padding(14)
        .background(
            LinearGradient(
                colors: [slate2.opacity(0.96), slate.opacity(0.92)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
        )
        .overlay(RoundedRectangle(cornerRadius: 22).stroke(ice.opacity(0.17), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 22))
        .shadow(color: .black.opacity(0.14), radius: 5, y: 2)
    }

    private var settingIcon: some View {
        Image(systemName: icon)
            .font(.title2)
            .foregroundStyle(cyan)
            .frame(width: 48, height: 48)
            .background(Color(hex: 0x0B3551))
            .clipShape(RoundedRectangle(cornerRadius: 14))
    }

    private var settingText: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title)
                .font(.headline)
                .foregroundStyle(.white)
                .lineLimit(2)
                .minimumScaleFactor(0.8)
            Text(subtitle)
                .font(.subheadline)
                .foregroundStyle(muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

extension SettingRow where Trailing == EmptyView {
    init(icon: String, title: String, subtitle: String) {
        self.init(icon: icon, title: title, subtitle: subtitle) { EmptyView() }
    }
}
