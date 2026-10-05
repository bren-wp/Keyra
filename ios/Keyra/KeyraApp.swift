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
    case onboarding, unlock, vault, collections, generator, add, detail, settings, security
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
    return [hasUpper, hasLower, hasDigit, hasSymbol].filter { $0 }.count >= 3
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

    static func key() throws -> SymmetricKey {
        if let existing = existingKeyData() {
            return SymmetricKey(data: existing)
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw KeyraError.keyUnavailable
        }
        let data = Data(bytes)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data
        ]

        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecSuccess {
            return SymmetricKey(data: data)
        }
        if status == errSecDuplicateItem, let existing = existingKeyData() {
            return SymmetricKey(data: existing)
        }
        throw KeyraError.keyUnavailable
    }
}

final class AuthStore {
    private let defaults = UserDefaults.standard
    private let legacyIterations = 120_000

    var isSetup: Bool {
        defaults.data(forKey: "master_hash") != nil && defaults.data(forKey: "master_salt") != nil
    }

    func create(password: String) -> Bool {
        var salt = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            return false
        }

        do {
            let saltData = Data(salt)
            let hash = try PasswordTools.derive(password, salt: saltData)
            defaults.set(saltData, forKey: "master_salt")
            defaults.set(PasswordTools.currentIterations, forKey: "master_iterations")
            defaults.set(hash, forKey: "master_hash")
            return true
        } catch {
            return false
        }
    }

    func verify(password: String) -> Bool {
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
        let ok = actual == expected

        if ok && iterations < PasswordTools.currentIterations,
           let upgraded = try? PasswordTools.derive(password, salt: salt) {
            defaults.set(PasswordTools.currentIterations, forKey: "master_iterations")
            defaults.set(upgraded, forKey: "master_hash")
        }
        return ok
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

    static func encrypt(_ items: [VaultItem], password: String) throws -> String {
        var salt = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt) == errSecSuccess else {
            throw KeyraError.keyUnavailable
        }
        let saltData = Data(salt)
        let key = SymmetricKey(data: try PasswordTools.derive(password, salt: saltData))
        let clear = try JSONEncoder().encode(items)
        let sealed = try AES.GCM.seal(clear, using: key)
        guard let combined = sealed.combined else { throw KeyraError.invalidBackup }
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

        let iterations: Int
        let saltPart: Substring
        let payloadPart: Substring
        if parts.count == 4, parts[0] == "KEYRA2", let parsed = Int(parts[1]), (100_000...2_000_000).contains(parsed) {
            iterations = parsed
            saltPart = parts[2]
            payloadPart = parts[3]
        } else if parts.count == 3, parts[0] == "KEYRA1" {
            iterations = 120_000
            saltPart = parts[1]
            payloadPart = parts[2]
        } else {
            throw KeyraError.invalidBackup
        }

        guard
            let salt = Data(base64Encoded: String(saltPart)),
            let combined = Data(base64Encoded: String(payloadPart))
        else { throw KeyraError.invalidBackup }

        let key = SymmetricKey(data: try PasswordTools.derive(password, salt: salt, iterations: iterations))
        let box = try AES.GCM.SealedBox(combined: combined)
        let clear = try AES.GCM.open(box, using: key)
        let decoded = try JSONDecoder().decode([VaultItem].self, from: clear)
        guard decoded.count <= maxVaultItems else {
            throw KeyraError.invalidBackup
        }
        return decoded
    }
}

func securityIssueIDs(_ items: [VaultItem]) -> Set<UUID> {
    let passwordItems = items.filter {
        ($0.kind == "Prijava" || $0.kind == "Wi-Fi") && !$0.password.isEmpty
    }
    let duplicateIDs = Set(
        Dictionary(grouping: passwordItems, by: { $0.password })
            .values
            .filter { $0.count > 1 }
            .flatMap { $0.map(\.id) }
    )
    let weakIDs = Set(passwordItems.filter { !isStrongPassword($0.password) }.map(\.id))
    return duplicateIDs.union(weakIDs)
}

func securityIssueCount(_ items: [VaultItem]) -> Int {
    securityIssueIDs(items).count
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

    private var sessionPassword: String?

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

    func cancelSetup() {
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

    func createVault(password: String) -> Bool {
        guard password.count >= 12 else {
            message = "Glavna lozinka mora imati najmanje 12 znakova."
            return false
        }
        do {
            try vault.save([])
        } catch {
            message = "Trezor nije moguće izraditi. Provjerite zaključavanje uređaja i pokušajte ponovno."
            return false
        }

        guard auth.create(password: password) else {
            vault.clear()
            message = "Zaštitu glavne lozinke nije moguće postaviti. Spremanje je poništeno."
            return false
        }

        finishInitialSetup(password: password, initialItems: [])
        return true
    }

    func importNewVault(password: String) -> Bool {
        guard password.count >= 12 else {
            message = "Glavna lozinka sigurnosne kopije mora imati najmanje 12 znakova."
            return false
        }
        guard let payload = UIPasteboard.general.string, !payload.isEmpty else {
            message = "Međuspremnik ne sadrži Keyra sigurnosnu kopiju."
            return false
        }
        guard payload.utf8.count <= 2_500_000 else {
            message = "Sigurnosna kopija je prevelika za siguran uvoz."
            return false
        }

        let imported: [VaultItem]
        do {
            imported = try PortableBackup.decrypt(payload, password: password)
            try vault.save(imported)
        } catch {
            message = "Sigurnosna kopija nije valjana, lozinka nije odgovarajuća ili spremanje nije uspjelo."
            return false
        }

        guard auth.create(password: password) else {
            vault.clear()
            message = "Zaštitu glavne lozinke nije moguće trajno spremiti. Uvoz je poništen."
            return false
        }

        if UIPasteboard.general.string == payload {
            UIPasteboard.general.items = []
        }
        finishInitialSetup(password: password, initialItems: imported)
        message = "Keyra trezor uspješno je uvezen."
        return true
    }

    private func finishInitialSetup(password: String, initialItems: [VaultItem]) {
        defaults.removeObject(forKey: "unlock_failed_attempts")
        defaults.removeObject(forKey: "unlock_lockout_until")
        isSetup = true
        importingNewVault = false
        sessionPassword = password
        items = initialItems
        selected = nil
        screen = .vault
    }

    func unlock(password: String) -> Bool {
        let now = Date().timeIntervalSince1970
        let lockoutUntil = defaults.double(forKey: "unlock_lockout_until")
        if lockoutUntil > now {
            let seconds = max(1, Int(ceil(lockoutUntil - now)))
            message = "Previše neuspjelih pokušaja. Pokušajte ponovno za \(seconds) s."
            return false
        }

        guard auth.verify(password: password) else {
            let attempts = defaults.integer(forKey: "unlock_failed_attempts") + 1
            let penalty: TimeInterval
            switch attempts {
            case 10...: penalty = 300
            case 7...: penalty = 60
            case 5...: penalty = 30
            default: penalty = 0
            }
            defaults.set(attempts, forKey: "unlock_failed_attempts")
            defaults.set(penalty > 0 ? now + penalty : 0, forKey: "unlock_lockout_until")
            message = penalty > 0
                ? "Previše neuspjelih pokušaja. Trezor je privremeno zaključan."
                : "Glavna lozinka nije ispravna."
            return false
        }

        defaults.removeObject(forKey: "unlock_failed_attempts")
        defaults.removeObject(forKey: "unlock_lockout_until")
        sessionPassword = password
        guard load() else {
            sessionPassword = nil
            return false
        }
        screen = .vault
        return true
    }

    func unlockBiometric() {
        let context = LAContext()
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            message = "Biometrijsko otključavanje nije dostupno."
            return
        }
        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "Otključajte svoj Keyra trezor.") { success, error in
            DispatchQueue.main.async {
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
        items = []
        selected = nil
        sessionPassword = nil
        vaultCategoryFilter = nil
        vaultTypeFilter = nil
        screen = .unlock
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

    func authorizeSensitive(reason: String, completion: @escaping () -> Void) {
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

        context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
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

    func copyBackup() {
        guard let password = sessionPassword else {
            message = "Za sigurnosnu kopiju prvo otključajte trezor glavnom lozinkom."
            return
        }
        do {
            SecureClipboard.copy(try PortableBackup.encrypt(items, password: password))
            message = "Šifrirana sigurnosna kopija kopirana je u međuspremnik i automatski će se ukloniti."
        } catch {
            message = "Sigurnosnu kopiju nije moguće izraditi."
        }
    }

    func importBackup() {
        guard let password = sessionPassword else {
            message = "Za uvoz prvo otključajte trezor glavnom lozinkom."
            return
        }
        guard let text = UIPasteboard.general.string else {
            message = "Međuspremnik ne sadrži sigurnosnu kopiju."
            return
        }
        guard text.utf8.count <= 2_500_000 else {
            message = "Sigurnosna kopija je prevelika za siguran uvoz."
            return
        }
        do {
            let imported = try PortableBackup.decrypt(text, password: password)
            try vault.save(imported)
            items = imported
            selected = nil
            if UIPasteboard.general.string == text {
                UIPasteboard.general.items = []
            }
            message = "Sigurnosna kopija uspješno je uvezena. Sadržaj kopije uklonjen je iz međuspremnika."
        } catch {
            message = "Sigurnosna kopija nije valjana ili lozinka nije odgovarajuća."
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

    var body: some View {
        ZStack(alignment: .bottom) {
            midnight.ignoresSafeArea()

            if splash {
                SplashView()
            } else {
                switch store.screen {
                case .onboarding: OnboardingView().keyraPageWidth(680)
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

            if (scenePhase != .active || screenCaptured) && !splash {
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
        .onChange(of: scenePhase) { _, phase in
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
    }

    @ViewBuilder
    private func header(compact: Bool) -> some View {
        HStack(spacing: compact ? 8 : 12) {
            KeyraMark(size: compact ? 42 : 50)
            VStack(alignment: .leading, spacing: 1) {
                Text("Keyra")
                    .font(.system(size: compact ? 27 : 31, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                Text(subtitle)
                    .font(.system(size: compact ? 9 : 10, weight: .medium))
                    .tracking(compact ? 1.2 : 2)
                    .foregroundStyle(muted)
                    .lineLimit(1)
                    .minimumScaleFactor(0.72)
            }
            Spacer(minLength: 4)
            Button {
                store.open(.security)
            } label: {
                ZStack(alignment: .topTrailing) {
                    Image(systemName: "bell")
                        .foregroundStyle(.white)
                        .frame(width: compact ? 30 : 36, height: compact ? 30 : 36)

                    if notificationCount > 0 {
                        Text(notificationCount > 9 ? "9+" : "\(notificationCount)")
                            .font(.system(size: 8, weight: .bold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 4)
                            .padding(.vertical, 1)
                            .background(danger)
                            .clipShape(Capsule())
                            .offset(x: 4, y: -3)
                    }
                }
            }
            .buttonStyle(.plain)
            .accessibilityLabel(
                notificationCount > 0
                    ? "Sigurnosna upozorenja: \(notificationCount)"
                    : "Nema sigurnosnih upozorenja"
            )
            Text("K")
                .font(.system(size: compact ? 12 : 14, weight: .bold))
                .frame(width: compact ? 36 : 42, height: compact ? 36 : 42)
                .overlay(Circle().stroke(cyan, lineWidth: 1))
        }
        .padding(.horizontal, compact ? 12 : 18)
        .padding(.vertical, compact ? 7 : 10)
    }
}

struct GlassCard<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(20)
            .background(slate.opacity(0.94))
            .overlay(RoundedRectangle(cornerRadius: 26).stroke(ice.opacity(0.36), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 26))
    }
}

struct FeatureCard: View {
    let icon: String
    let title: String
    let subtitle: String
    var compact = false

    var body: some View {
        HStack(spacing: compact ? 10 : 14) {
            Image(systemName: icon)
                .font(compact ? .headline : .title2)
                .foregroundStyle(cyan)
                .frame(width: compact ? 40 : 48, height: compact ? 40 : 48)
                .background(Color(hex: 0x0A2D3C))
                .clipShape(RoundedRectangle(cornerRadius: compact ? 12 : 15))
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(compact ? .subheadline.bold() : .headline)
                    .foregroundStyle(.white)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                Text(subtitle)
                    .font(compact ? .caption : .subheadline)
                    .foregroundStyle(muted)
                    .lineLimit(compact ? 1 : 2)
                    .minimumScaleFactor(0.8)
            }
            Spacer(minLength: 0)
        }
        .padding(compact ? 10 : 14)
        .background(slate.opacity(0.92))
        .overlay(RoundedRectangle(cornerRadius: compact ? 17 : 20).stroke(cyan.opacity(0.34), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: compact ? 17 : 20))
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
            let compact = proxy.size.height < 720 || proxy.size.width < 360

            VStack(spacing: 0) {
                ScrollView {
                    VStack(spacing: compact ? 7 : 11) {
                        KeyraMark(size: compact ? 64 : 82)
                            .padding(.top, compact ? 8 : 18)

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

                        OnboardingVaultHero(compact: compact)
                            .padding(.top, compact ? 3 : 7)

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

                        FeatureCard(
                            icon: "lock.fill",
                            title: "Potpuno šifrirano",
                            subtitle: "Vaši podaci ostaju na vašem uređaju.",
                            compact: compact
                        )
                        FeatureCard(
                            icon: "faceid",
                            title: "Privatnost u osnovi",
                            subtitle: "Stvoreno za vaš mir.",
                            compact: compact
                        )
                        FeatureCard(
                            icon: "rectangle.on.rectangle",
                            title: "Radi svugdje",
                            subtitle: "Pregledno na Androidu i iOS-u.",
                            compact: compact
                        )
                    }
                    .padding(.horizontal, compact ? 16 : 22)
                    .padding(.bottom, 8)
                }

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
                }
                .padding(.horizontal, compact ? 16 : 22)
                .padding(.top, 8)
                .padding(.bottom, max(proxy.safeAreaInsets.bottom, 8))
            }
        }
    }
}

struct UnlockView: View {
    @EnvironmentObject var store: KeyraStore
    @State private var password = ""
    @State private var confirm = ""
    @State private var reveal = false

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
                            ? "Kopirajte šifriranu Keyra sigurnosnu kopiju u međuspremnik i unesite njezinu glavnu lozinku."
                            : (creating
                                ? "Postavite glavnu lozinku kojom ćete otključavati svoj trezor."
                                : "Unesite glavnu lozinku kako biste pristupili svom sigurnom trezoru.")
                    )
                    .foregroundStyle(muted)

                    SecretField(title: "Glavna lozinka", text: $password, reveal: $reveal)
                    if creating && !importing {
                        SecretField(title: "Ponovite glavnu lozinku", text: $confirm, reveal: $reveal)
                    }
                    if importing {
                        Text("Uvoz neće zamijeniti podatke ako provjera ili trajno spremanje ne uspiju.")
                            .font(.caption)
                            .foregroundStyle(muted)
                    }

                    Button {
                        if importing {
                            _ = store.importNewVault(password: password)
                        } else if creating {
                            if password != confirm { store.message = "Lozinke se ne podudaraju." }
                            else { _ = store.createVault(password: password) }
                        } else {
                            _ = store.unlock(password: password)
                        }
                    } label: {
                        HStack {
                            Image(systemName: "lock.fill")
                            Text(importing ? "Uvezi trezor" : (creating ? "Izradi trezor" : "Otključaj")).fontWeight(.bold)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 54)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(midnight)
                    .background(cyan)
                    .clipShape(Capsule())

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
    }
}

struct SecretField: View {
    let title: String
    @Binding var text: String
    @Binding var reveal: Bool

    var body: some View {
        HStack {
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
            }
        }
        .padding()
        .background(midnight.opacity(0.62))
        .overlay(RoundedRectangle(cornerRadius: 18).stroke(ice.opacity(0.38), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 18))
        .foregroundStyle(.white)
    }
}

struct BottomBar: View {
    @EnvironmentObject var store: KeyraStore

    var body: some View {
        HStack(spacing: 2) {
            BottomItem(icon: "house", title: "Trezor", screen: .vault)
            BottomItem(icon: "arrow.triangle.2.circlepath", title: "Generator", screen: .generator)
            BottomItem(icon: "square.grid.2x2", title: "Kolekcije", screen: .collections)
            BottomItem(icon: "gearshape", title: "Postavke", screen: .settings)
        }
        .padding(.vertical, 7)
        .background(slate.opacity(0.97))
        .overlay(RoundedRectangle(cornerRadius: 22).stroke(ice.opacity(0.25), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 22))
        .padding(.horizontal, 12)
        .padding(.bottom, 3)
        .frame(maxWidth: 820)
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder
    private func BottomItem(icon: String, title: String, screen: KeyraScreen) -> some View {
        let selected = store.screen == screen
        Button {
            store.open(screen)
        } label: {
            VStack(spacing: 2) {
                Image(systemName: icon)
                    .font(.system(size: 19, weight: .semibold))
                Text(title)
                    .font(.caption2)
                    .fontWeight(selected ? .bold : .regular)
                    .lineLimit(1)
                    .minimumScaleFactor(0.72)
                Capsule()
                    .fill(cyan)
                    .frame(width: selected ? 24 : 0, height: 2)
                    .padding(.top, 1)
            }
            .foregroundStyle(selected ? cyan : muted)
            .frame(maxWidth: .infinity, minHeight: 46)
            .background(selected ? cyan.opacity(0.11) : Color.clear)
            .overlay(
                RoundedRectangle(cornerRadius: 17)
                    .stroke(selected ? cyan.opacity(0.30) : Color.clear, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 17))
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
        let grouped = Dictionary(grouping: passwordItems.filter { !$0.password.isEmpty }, by: { $0.password })
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
                Menu {
                    Button(newestFirst ? "Poredaj A–Ž" : "Poredaj po nedavnim") {
                        newestFirst.toggle()
                    }
                    Button("Prikaži sve") {
                        filter = "Sve"
                        search = ""
                        store.clearVaultCategoryFilter()
                    }
                } label: {
                    Image(systemName: "slider.horizontal.3").foregroundStyle(ice)
                }
                .accessibilityLabel("Filtri i sortiranje")
            }
            .padding()
            .background(slate)
            .overlay(RoundedRectangle(cornerRadius: 24).stroke(ice.opacity(0.35), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 24))
            .padding(.horizontal, 18)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(["Sve","Prijava","Bilješka","Kartica","Identitet","Wi-Fi","Favoriti"], id: \.self) { value in
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
                                    case "Favoriti": return "star"
                                    default: return "square.grid.2x2"
                                    }
                                }())
                                Text({
                                    switch value {
                                    case "Prijava": return "Prijave"
                                    case "Bilješka": return "Bilješke"
                                    case "Kartica": return "Kartice"
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
                        Text("Kategorija: \(category)")
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
                    Summary(value: "\(passwordItems.filter { !$0.password.isEmpty && !isStrongPassword($0.password) }.count)", label: "Slabe", accent: danger)
                    Summary(value: "\(duplicates.count)", label: "Ponovljene", accent: indigo)
                }

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        Summary(value: "\(store.items.count)", label: "Ukupno", accent: cyan).frame(width: 112)
                        Summary(value: "\(passwordItems.filter { !$0.password.isEmpty && !isStrongPassword($0.password) }.count)", label: "Slabe", accent: danger).frame(width: 112)
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

                Button { store.addNew() } label: {
                    Image(systemName: "plus")
                        .font(.title2.bold())
                        .foregroundStyle(midnight)
                        .frame(width: 44, height: 44)
                        .background(cyan)
                        .clipShape(Circle())
                }
            }
            .padding(.horizontal, 18)
            .padding(.vertical, 12)

            ScrollView {
                LazyVStack(spacing: 9) {
                    ForEach(filtered) { item in
                        VaultRow(item: item, duplicated: duplicates.contains(item.id))
                            .onTapGesture { store.select(item) }
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
                                ? "Dodajte prvu prijavu, sigurnu bilješku, karticu, identitet ili Wi‑Fi."
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

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).font(.system(size: 30, weight: .black)).foregroundStyle(.white)
            Text(label).font(.caption).foregroundStyle(muted)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(accent.opacity(0.65), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }
}

struct VaultRow: View {
    let item: VaultItem
    let duplicated: Bool

    private var isPasswordItem: Bool { item.kind == "Prijava" || item.kind == "Wi-Fi" }

    private var state: (String, Color) {
        if duplicated { return ("Ponovno korištena", danger) }
        if isPasswordItem && !item.password.isEmpty && !isStrongPassword(item.password) { return ("Potrebno ažuriranje", warn) }
        switch item.kind {
        case "Bilješka", "Kartica": return ("Zaštićena", good)
        case "Identitet": return ("Zaštićen", good)
        default: return ("Snažna", good)
        }
    }

    private var icon: String {
        switch item.kind {
        case "Bilješka": return "doc.text.fill"
        case "Kartica": return "creditcard.fill"
        case "Identitet": return "person.text.rectangle.fill"
        case "Wi-Fi": return "wifi"
        default: return "lock.fill"
        }
    }

    private var accent: Color {
        switch item.kind {
        case "Bilješka": return indigo
        case "Kartica": return warn
        case "Identitet": return Color(hex: 0xB48CFF)
        case "Wi-Fi": return Color(hex: 0x22BDF7)
        default: return cyan
        }
    }

    private var subtitle: String {
        switch item.kind {
        case "Kartica":
            if let number = item.extraFields["Broj kartice"], !number.isEmpty {
                return "•••• " + String(number.suffix(4))
            }
            return item.category
        case "Identitet":
            return item.extraFields["Puno ime"]?.isEmpty == false ? item.extraFields["Puno ime"]! : item.category
        case "Wi-Fi":
            if let network = item.extraFields["Naziv mreže"], !network.isEmpty { return network }
            return item.username.isEmpty ? item.category : item.username
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
    @State private var selectedType = "Prijava"

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
            let typeMatch = selectedType == "Favoriti" ? item.favorite : item.kind == selectedType
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

    private var recentNotes: [VaultItem] {
        Array(
            store.items
                .filter {
                    $0.kind == "Bilješka" &&
                    (search.isEmpty || $0.title.localizedCaseInsensitiveContains(search) || $0.notes.localizedCaseInsensitiveContains(search))
                }
                .sorted { $0.updatedAt > $1.updatedAt }
                .prefix(3)
        )
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "MOJ TREZOR")

            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Kolekcije")
                        .font(.system(size: 42, weight: .black))
                        .foregroundStyle(.white)
                    Text("Organizirajte podatke. Pronađite ih odmah.")
                        .foregroundStyle(muted)
                }
                Spacer()
            }
            .padding(.horizontal, 18)

            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(ice)
                TextField("Pretražite lozinke, bilješke, kartice...", text: $search)
                    .foregroundStyle(.white)
                Menu {
                    ForEach(["Prijava", "Bilješka", "Kartica", "Identitet", "Wi-Fi", "Favoriti"], id: \.self) { value in
                        Button({
                            switch value {
                            case "Prijava": return "Lozinke"
                            case "Bilješka": return "Bilješke"
                            case "Kartica": return "Kartice"
                            default: return value
                            }
                        }()) {
                            selectedType = value
                        }
                    }
                    Button("Očisti pretragu") {
                        search = ""
                    }
                } label: {
                    Image(systemName: "slider.horizontal.3").foregroundStyle(ice)
                }
                .accessibilityLabel("Filtriraj kolekcije")
            }
            .padding()
            .background(slate)
            .overlay(RoundedRectangle(cornerRadius: 24).stroke(ice.opacity(0.35), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 24))
            .padding(.horizontal, 18)
            .padding(.top, 10)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(["Prijava","Bilješka","Kartica","Identitet","Wi-Fi","Favoriti"], id: \.self) { value in
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
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 150, maximum: 280), spacing: 10)],
                    spacing: 10
                ) {
                    ForEach(categories.indices, id: \.self) { index in
                        let name = categories[index].0
                        let accent = categories[index].1
                        let icon = categories[index].2
                        HStack(spacing: 10) {
                            Image(systemName: icon)
                                .foregroundStyle(accent)
                                .frame(width: 44, height: 44)
                                .background(accent.opacity(0.18))
                                .clipShape(RoundedRectangle(cornerRadius: 13))
                            VStack(alignment: .leading, spacing: 4) {
                                Text(name).font(.headline).foregroundStyle(.white)
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
                    }
                }
                .padding(.horizontal, 18)

                VStack(alignment: .leading, spacing: 10) {
                    Text("Nedavne bilješke")
                        .font(.title2.bold())
                        .foregroundStyle(.white)
                    Text("Vaše najnovije bilješke i sigurne informacije.")
                        .foregroundStyle(muted)

                    ForEach(recentNotes) { item in
                        Button {
                            store.select(item)
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: "doc.text.fill")
                                    .foregroundStyle(indigo)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(item.title).fontWeight(.bold).foregroundStyle(.white)
                                    Text(item.notes).lineLimit(1).foregroundStyle(muted)
                                }
                                Spacer()
                                Image(systemName: "ellipsis").foregroundStyle(muted)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(14)
                            .background(slate)
                            .clipShape(RoundedRectangle(cornerRadius: 18))
                        }
                        .buttonStyle(.plain)
                    }

                    if recentNotes.isEmpty {
                        Text("Još nema sigurnih bilješki.")
                            .foregroundStyle(muted)
                            .padding(.vertical, 18)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.top, 12)
                .padding(.bottom, 100)
            }
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
                        Text("Zadana jačina")
                            .font(.headline)
                            .foregroundStyle(.white)

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                ForEach(["Jednostavna", "Snažna", "Maksimalna", "Prilagodi"], id: \.self) { name in
                                    Button(name) {
                                        if name != "Prilagodi" {
                                            applyPreset(name)
                                        }
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
                    }

                    GlassCard {
                        HStack {
                            Text("Duljina lozinke").font(.headline).foregroundStyle(.white)
                            Spacer()
                            Text("\(Int(length))").font(.title3.bold()).foregroundStyle(cyan)
                        }
                        Slider(value: $length, in: 8...64, step: 1) { _ in refresh() }
                            .tint(cyan)
                    }

                    GlassCard {
                        Text("Vrste znakova").font(.headline).foregroundStyle(.white)
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
    @State private var reveal = false

    private let original: VaultItem?

    private var itemLabel: String {
        switch type {
        case "Bilješka": return "bilješku"
        case "Kartica": return "karticu"
        case "Identitet": return "identitet"
        case "Wi-Fi": return "Wi-Fi"
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
        default: return "Sigurno spremite svoje vjerodajnice"
        }
    }

    private var saveLabel: String {
        switch type {
        case "Bilješka": return "Spremi bilješku"
        case "Kartica": return "Spremi karticu"
        case "Identitet": return "Spremi identitet"
        case "Wi-Fi": return "Spremi Wi-Fi"
        default: return "Spremi prijavu"
        }
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
        switch item?.kind {
        case "Kartica":
            _field1 = State(initialValue: extra["Vlasnik kartice"] ?? "")
            _field2 = State(initialValue: extra["Broj kartice"] ?? "")
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
        default:
            _field1 = State(initialValue: "")
            _field2 = State(initialValue: "")
            _field3 = State(initialValue: "")
            _field4 = State(initialValue: "")
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button {
                    store.open(original == nil ? .vault : .detail)
                } label: {
                    Image(systemName: "chevron.left")
                        .font(.title2)
                        .foregroundStyle(.white)
                }
                KeyraMark(size: 38)
                Text("Keyra").font(.title.bold()).foregroundStyle(.white)
                Spacer()
            }
            .padding()

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
                            ForEach(["Prijava","Bilješka","Kartica","Identitet","Wi-Fi"], id: \.self) { value in
                                Button {
                                    if original == nil {
                                        type = value
                                        field1 = ""
                                        field2 = ""
                                        field3 = ""
                                        field4 = ""
                                    }
                                } label: {
                                    HStack(spacing: 6) {
                                        Image(systemName: {
                                            switch value {
                                            case "Bilješka": return "doc.text"
                                            case "Kartica": return "creditcard"
                                            case "Identitet": return "person.text.rectangle"
                                            case "Wi-Fi": return "wifi"
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
                        KeyraField(title: "Broj kartice", text: $field2)
                            .keyboardType(.numberPad)
                            .onChange(of: field2) { _, value in
                                field2 = String(value.filter(\.isNumber).prefix(19))
                            }
                        KeyraField(title: "Vrijedi do (MM/GG)", text: $field3)
                            .keyboardType(.numberPad)
                            .onChange(of: field3) { _, value in
                                let formatted = formatCardExpiry(value)
                                if formatted != value {
                                    field3 = formatted
                                }
                            }
                        KeyraField(title: "Sigurnosni kod", text: $field4)
                            .keyboardType(.numberPad)
                            .onChange(of: field4) { _, value in
                                field4 = String(value.filter(\.isNumber).prefix(4))
                            }
                    }

                    if type == "Identitet" {
                        KeyraField(title: "Puno ime", text: $field1)
                        KeyraField(title: "Broj dokumenta", text: $field2)
                        KeyraField(title: "Datum isteka", text: $field3)
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
                            ForEach(["Osobno","Posao","Financije","Društvene mreže","Kupovina","Putovanja","Zdravlje","Ostalo"], id: \.self) { value in
                                Button(value) { category = value }
                                    .buttonStyle(.plain)
                                    .foregroundStyle(category == value ? midnight : .white)
                                    .padding(.horizontal, 14)
                                    .padding(.vertical, 9)
                                    .background(category == value ? cyan : slate)
                                    .clipShape(Capsule())
                            }
                        }
                    }

                    Button {
                        let cleanTitle = title.trimmingCharacters(in: .whitespacesAndNewlines)
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
                            if type == "Kartica", !field2.isEmpty, !(12...19).contains(field2.count) {
                                return "Broj kartice mora sadržavati između 12 i 19 znamenki."
                            }
                            if type == "Kartica", !field4.isEmpty, !(3...4).contains(field4.count) {
                                return "Sigurnosni kod mora sadržavati 3 ili 4 znamenke."
                            }
                            if type == "Kartica", !field3.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                let expiry = field3.trimmingCharacters(in: .whitespacesAndNewlines)
                                let pattern = "^(0[1-9]|1[0-2])/(\\d{2}|\\d{4})$"
                                if expiry.range(of: pattern, options: .regularExpression) == nil {
                                    return "Datum isteka kartice unesite u obliku MM/GG ili MM/GGGG."
                                }
                            }
                            if type == "Identitet",
                               field1.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                               field2.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                                return "Unesite puno ime ili broj dokumenta."
                            }
                            return nil
                        }()
                        if let validationMessage {
                            store.message = validationMessage
                            return
                        }

                        let extra: [String: String]
                        switch type {
                        case "Kartica":
                            extra = [
                                "Vlasnik kartice": field1,
                                "Broj kartice": field2,
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
                                category: category,
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
            .padding()
            .foregroundStyle(.white)
            .background(slate)
            .overlay(RoundedRectangle(cornerRadius: 18).stroke(ice.opacity(0.35), lineWidth: 1))
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
    @State private var confirmDelete = false

    var body: some View {
        if let item = store.selected {
            let isPasswordItem = item.kind == "Prijava" || item.kind == "Wi-Fi"
            let securityLabel = isPasswordItem
                ? (item.password.isEmpty ? "Bez lozinke" : (isStrongPassword(item.password) ? "Snažna" : "Potrebno ažuriranje"))
                : "Zaštićena"
            let securityColor: Color = {
                switch securityLabel {
                case "Snažna", "Zaštićena": return good
                case "Potrebno ažuriranje": return warn
                default: return muted
                }
            }()
            VStack(spacing: 0) {
                HStack {
                    Button { store.open(.vault) } label: {
                        Image(systemName: "chevron.left").font(.title2).foregroundStyle(.white)
                    }

                    Image(systemName: {
                        switch item.kind {
                        case "Bilješka": return "doc.text.fill"
                        case "Kartica": return "creditcard.fill"
                        case "Identitet": return "person.text.rectangle.fill"
                        case "Wi-Fi": return "wifi"
                        default: return "lock.fill"
                        }
                    }())
                    .foregroundStyle(cyan)
                    .frame(width: 52, height: 52)
                    .background(cyan.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 16))

                    VStack(alignment: .leading) {
                        Text(item.title)
                            .font(.system(size: 32, weight: .black))
                            .foregroundStyle(.white)
                            .lineLimit(2)
                            .minimumScaleFactor(0.72)
                        Text(item.kind + " • " + item.category)
                            .foregroundStyle(muted)
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                    Spacer()
                    if item.favorite { Image(systemName: "star.fill").foregroundStyle(warn) }
                }
                .padding(18)

                ScrollView {
                    VStack(spacing: 10) {
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
    @State private var search = ""
    @State private var confirmImport = false

    private func runProtectedImport() {
        store.authorizeSensitive(reason: "Potvrdite identitet za uvoz sigurnosne kopije.") {
            store.importBackup()
        }
    }

    private func matches(_ values: String...) -> Bool {
        search.isEmpty || values.contains { $0.localizedCaseInsensitiveContains(search) }
    }

    private var accountVisible: Bool {
        matches(
            "Biometrijsko otključavanje",
            "Potvrda prije prikaza tajni",
            "Automatsko zaključavanje",
            "Provjera sigurnosti"
        )
    }

    private var dataVisible: Bool {
        matches("Kopiraj sigurnosnu kopiju", "Uvezi sigurnosnu kopiju", "sigurnosna kopija")
    }

    private var preferenceVisible: Bool {
        matches("Tamni način", "tamni izgled")
    }

    private var privacyVisible: Bool {
        matches("O aplikaciji Keyra", "Zaključaj trezor", "sigurnost privatnost")
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "POSTAVKE I SIGURNOST")

            HStack(spacing: 10) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(ice)
                TextField("Pretražite postavke...", text: $search)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .foregroundStyle(.white)
                if !search.isEmpty {
                    Button {
                        search = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(muted)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Očisti pretragu")
                }
            }
            .padding(.horizontal, 16)
            .frame(height: 54)
            .background(slate)
            .overlay(RoundedRectangle(cornerRadius: 24).stroke(ice.opacity(0.35), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 24))
            .padding(.horizontal, 18)
            .padding(.vertical, 4)

            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if accountVisible {
                        SectionLabel("RAČUN I SIGURNOST")
                    }

                    if matches("Biometrijsko otključavanje", "biometrija") {
                        SettingRow(icon: "fingerprint", title: "Biometrijsko otključavanje", subtitle: "Brz i siguran pristup trezoru.") {
                            Toggle("", isOn: Binding(get: { store.biometricEnabled }, set: { store.toggleBiometric($0) }))
                                .labelsHidden()
                                .tint(cyan)
                        }
                    }

                    if matches("Potvrda prije prikaza tajni", "osjetljive vrijednosti", "potvrda identiteta") {
                        SettingRow(
                            icon: "eye",
                            title: "Potvrda prije prikaza tajni",
                            subtitle: "Tražite biometriju ili šifru uređaja prije prikaza i kopiranja osjetljivih podataka."
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
                    }

                    if matches("Automatsko zaključavanje", "zaključavanje") {
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
                    }

                    if matches("Provjera sigurnosti", "slabe lozinke", "ponovljene lozinke") {
                        Button {
                            store.open(.security)
                        } label: {
                            SettingRow(
                                icon: "shield.checkered",
                                title: "Provjera sigurnosti",
                                subtitle: "Pronađite slabe i ponovljene lozinke."
                            ) {
                                Image(systemName: "chevron.right").foregroundStyle(ice)
                            }
                        }
                        .buttonStyle(.plain)
                    }

                    if dataVisible {
                        SectionLabel("UPRAVLJANJE PODACIMA")
                    }

                    if matches("Kopiraj sigurnosnu kopiju", "izvoz", "sigurnosna kopija") {
                        SettingRow(icon: "square.and.arrow.up", title: "Kopiraj sigurnosnu kopiju", subtitle: "Stvorite šifriranu kopiju trezora.") {
                            Button {
                                store.authorizeSensitive(reason: "Potvrdite identitet za izradu sigurnosne kopije.") {
                                    store.copyBackup()
                                }
                            } label: {
                                Image(systemName: "doc.on.doc").foregroundStyle(cyan)
                            }
                            .buttonStyle(.plain)
                        }
                    }

                    if matches("Uvezi sigurnosnu kopiju", "uvoz", "sigurnosna kopija") {
                        SettingRow(
                            icon: "square.and.arrow.down",
                            title: "Uvezi sigurnosnu kopiju",
                            subtitle: "Zamijenite trenutačni trezor šifriranom kopijom iz međuspremnika."
                        ) {
                            Button {
                                confirmImport = true
                            } label: {
                                Image(systemName: "arrow.down.doc").foregroundStyle(cyan)
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel("Uvezi sigurnosnu kopiju")
                        }
                    }

                    if preferenceVisible {
                        SectionLabel("PREFERENCIJE")
                    }

                    if matches("Tamni način", "tamni izgled") {
                        SettingRow(icon: "moon", title: "Tamni način", subtitle: "Čistije i ugodnije iskustvo za oči.") {
                            Text("Uvijek uključen")
                                .font(.caption)
                                .foregroundStyle(cyan)
                        }
                    }

                    if privacyVisible {
                        SectionLabel("SIGURNOST I PRIVATNOST")
                    }

                    if matches("O aplikaciji Keyra", "verzija") {
                        SettingRow(
                            icon: "info.circle",
                            title: "O aplikaciji Keyra",
                            subtitle: "Verzija 0.5.0 • Vaši ključevi. Vaši podaci. Uvijek vaši."
                        )
                    }

                    if matches("Zaključaj trezor", "zaključavanje") {
                        Button {
                            store.lock()
                        } label: {
                            Label("Zaključaj trezor", systemImage: "lock")
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                        }
                        .buttonStyle(.plain)
                        .foregroundStyle(.white)
                        .overlay(Capsule().stroke(ice.opacity(0.4), lineWidth: 1))
                    }

                    if !search.isEmpty && !accountVisible && !dataVisible && !preferenceVisible && !privacyVisible {
                        GlassCard {
                            Image(systemName: "magnifyingglass")
                                .foregroundStyle(cyan)
                            Text("Nema rezultata")
                                .font(.headline)
                                .foregroundStyle(.white)
                            Text("Pokušajte s drugim pojmom za pretragu postavki.")
                                .foregroundStyle(muted)
                        }
                    }
                }
                .padding(18)
                .padding(.bottom, 100)
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .confirmationDialog(
            "Uvesti sigurnosnu kopiju?",
            isPresented: $confirmImport,
            titleVisibility: .visible
        ) {
            Button("Uvezi i zamijeni", role: .destructive) {
                runProtectedImport()
            }
            Button("Odustani", role: .cancel) {}
        } message: {
            Text(
                "Trenutni sadržaj trezora bit će zamijenjen sadržajem iz sigurnosne kopije. " +
                "Prije nastavka provjerite da je kopija ispravna."
            )
        }
    }
}

struct SecurityCenterView: View {
    @EnvironmentObject var store: KeyraStore

    private var duplicateIDs: Set<UUID> {
        let passwordItems = store.items.filter { ($0.kind == "Prijava" || $0.kind == "Wi-Fi") && !$0.password.isEmpty }
        let groups = Dictionary(grouping: passwordItems, by: { $0.password })
        return Set(groups.values.filter { $0.count > 1 }.flatMap { $0.map(\.id) })
    }

    private var weakItems: [VaultItem] {
        store.items.filter { ($0.kind == "Prijava" || $0.kind == "Wi-Fi") && !$0.password.isEmpty && !isStrongPassword($0.password) }
    }

    private var strongItems: [VaultItem] {
        store.items.filter { ($0.kind == "Prijava" || $0.kind == "Wi-Fi") && isStrongPassword($0.password) && !duplicateIDs.contains($0.id) }
    }

    private var score: Int? {
        let passwordItems = store.items.filter { ($0.kind == "Prijava" || $0.kind == "Wi-Fi") && !$0.password.isEmpty }
        guard !passwordItems.isEmpty else { return nil }
        return Int((Double(strongItems.count) / Double(passwordItems.count)) * 100)
    }

    private var issues: [VaultItem] {
        Array(Dictionary(uniqueKeysWithValues:
            (weakItems + store.items.filter { duplicateIDs.contains($0.id) }).map { ($0.id, $0) }
        ).values)
        .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "SIGURNOST")
            ScrollView {
                VStack(spacing: 12) {
                    GlassCard {
                        Text("Ocjena sigurnosti")
                            .foregroundStyle(muted)
                        HStack(alignment: .lastTextBaseline, spacing: 2) {
                            Text(score.map(String.init) ?? "—")
                                .font(.system(size: 54, weight: .black))
                                .foregroundStyle(score == nil ? muted : ((score ?? 0) >= 80 ? good : warn))
                            Text("/100")
                                .font(.headline)
                                .foregroundStyle(muted)
                        }
                        ProgressView(value: Double(score ?? 0), total: 100)
                            .tint(score == nil ? muted : ((score ?? 0) >= 80 ? good : warn))
                        Text({
                            guard let score else {
                                return "Dodajte barem jednu lozinku kako bi Keyra mogla izračunati ocjenu sigurnosti."
                            }
                            return score >= 80
                                ? "Vaš trezor izgleda dobro zaštićen."
                                : "Pregledajte stavke koje zahtijevaju pažnju."
                        }())
                        .foregroundStyle(muted)
                    }

                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: 10) {
                            Summary(value: "\(strongItems.count)", label: "Snažne", accent: good)
                            Summary(value: "\(weakItems.count)", label: "Slabe", accent: warn)
                            Summary(value: "\(duplicateIDs.count)", label: "Ponovljene", accent: danger)
                        }

                        ScrollView(.horizontal, showsIndicators: false) {
                            HStack(spacing: 8) {
                                Summary(value: "\(strongItems.count)", label: "Snažne", accent: good)
                                    .frame(width: 110)
                                Summary(value: "\(weakItems.count)", label: "Slabe", accent: warn)
                                    .frame(width: 110)
                                Summary(value: "\(duplicateIDs.count)", label: "Ponovljene", accent: danger)
                                    .frame(width: 124)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 10) {
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
                                Image(systemName: "checkmark.shield.fill").foregroundStyle(good)
                                Text("Nisu pronađene slabe ili ponovljene lozinke.")
                                    .foregroundStyle(.white)
                                Spacer()
                            }
                            .padding(18)
                            .background(good.opacity(0.10))
                            .overlay(RoundedRectangle(cornerRadius: 20).stroke(good.opacity(0.55), lineWidth: 1))
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

struct SectionLabel: View {
    let value: String
    init(_ value: String) { self.value = value }

    var body: some View {
        Text(value)
            .font(.caption)
            .tracking(2)
            .foregroundStyle(ice)
            .padding(.top, 8)
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
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(ice.opacity(0.18), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
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
