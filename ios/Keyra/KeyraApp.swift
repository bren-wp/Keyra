import SwiftUI
import CryptoKit
import LocalAuthentication
import Security
import UIKit

private let midnight = Color(hex: 0x06111F)
private let slate = Color(hex: 0x0B2034)
private let slate2 = Color(hex: 0x121826)
private let cyan = Color(hex: 0x00E5D1)
private let ice = Color(hex: 0x7DD3FC)
private let indigo = Color(hex: 0x6366F1)
private let muted = Color(hex: 0xAABBD5)
private let good = Color(hex: 0x22E3B0)
private let warn = Color(hex: 0xFFC247)
private let danger = Color(hex: 0xFF5B6E)

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

enum KeyraScreen: Equatable {
    case onboarding, unlock, vault, collections, generator, add, detail, settings
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
    var updatedAt = Date()
}

enum KeyraError: Error {
    case invalidData
    case keyUnavailable
    case invalidBackup
}

enum PasswordTools {
    static func derive(_ password: String, salt: Data, iterations: Int = 120_000, keyLength: Int = 32) -> Data {
        let passwordData = Data(password.utf8)
        let key = SymmetricKey(data: passwordData)
        var blockIndex = UInt32(1).bigEndian
        var saltBlock = Data(salt)
        withUnsafeBytes(of: &blockIndex) { saltBlock.append(contentsOf: $0) }

        var u = Data(HMAC<SHA256>.authenticationCode(for: saltBlock, using: key))
        var result = [UInt8](u)

        if iterations > 1 {
            for _ in 2...iterations {
                u = Data(HMAC<SHA256>.authenticationCode(for: u, using: key))
                let bytes = [UInt8](u)
                for i in 0..<result.count { result[i] ^= bytes[i] }
            }
        }
        return Data(result.prefix(keyLength))
    }

    static func generate(length: Int, upper: Bool, lower: Bool, numbers: Bool, symbols: Bool) -> String {
        var pool = ""
        if upper { pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }
        if lower { pool += "abcdefghijklmnopqrstuvwxyz" }
        if numbers { pool += "0123456789" }
        if symbols { pool += "!@#$%&*+-_=.?" }
        if pool.isEmpty { pool = "abcdefghijklmnopqrstuvwxyz" }

        var rng = SystemRandomNumberGenerator()
        let chars = Array(pool)
        return String((0..<length).compactMap { _ in chars.randomElement(using: &rng) })
    }
}

enum KeychainVault {
    private static let service = "com.keyra.app.vault"
    private static let account = "encryption-key"

    static func key() throws -> SymmetricKey {
        let read: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var output: CFTypeRef?
        let status = SecItemCopyMatching(read as CFDictionary, &output)
        if status == errSecSuccess, let data = output as? Data {
            return SymmetricKey(data: data)
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
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: data
        ]
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            throw KeyraError.keyUnavailable
        }
        return SymmetricKey(data: data)
    }
}

final class AuthStore {
    private let defaults = UserDefaults.standard

    var isSetup: Bool {
        defaults.data(forKey: "master_hash") != nil && defaults.data(forKey: "master_salt") != nil
    }

    func create(password: String) {
        var salt = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt)
        let saltData = Data(salt)
        let hash = PasswordTools.derive(password, salt: saltData)
        defaults.set(saltData, forKey: "master_salt")
        defaults.set(hash, forKey: "master_hash")
    }

    func verify(password: String) -> Bool {
        guard
            let salt = defaults.data(forKey: "master_salt"),
            let expected = defaults.data(forKey: "master_hash")
        else { return false }
        return PasswordTools.derive(password, salt: salt) == expected
    }
}

final class EncryptedVault {
    private let defaults = UserDefaults.standard

    func save(_ items: [VaultItem]) throws {
        let data = try JSONEncoder().encode(items)
        let sealed = try AES.GCM.seal(data, using: KeychainVault.key())
        guard let combined = sealed.combined else { throw KeyraError.invalidData }
        defaults.set(combined, forKey: "vault_blob")
    }

    func load() throws -> [VaultItem] {
        guard let data = defaults.data(forKey: "vault_blob") else { return [] }
        let box = try AES.GCM.SealedBox(combined: data)
        let clear = try AES.GCM.open(box, using: KeychainVault.key())
        return try JSONDecoder().decode([VaultItem].self, from: clear)
    }
}

enum PortableBackup {
    static func encrypt(_ items: [VaultItem], password: String) throws -> String {
        var salt = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, salt.count, &salt)
        let saltData = Data(salt)
        let key = SymmetricKey(data: PasswordTools.derive(password, salt: saltData))
        let clear = try JSONEncoder().encode(items)
        let sealed = try AES.GCM.seal(clear, using: key)
        guard let combined = sealed.combined else { throw KeyraError.invalidBackup }
        return "KEYRA1." + saltData.base64EncodedString() + "." + combined.base64EncodedString()
    }

    static func decrypt(_ text: String, password: String) throws -> [VaultItem] {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard
            parts.count == 3,
            parts[0] == "KEYRA1",
            let salt = Data(base64Encoded: String(parts[1])),
            let combined = Data(base64Encoded: String(parts[2]))
        else { throw KeyraError.invalidBackup }

        let key = SymmetricKey(data: PasswordTools.derive(password, salt: salt))
        let box = try AES.GCM.SealedBox(combined: combined)
        let clear = try AES.GCM.open(box, using: key)
        return try JSONDecoder().decode([VaultItem].self, from: clear)
    }
}

final class KeyraStore: ObservableObject {
    private let auth = AuthStore()
    private let vault = EncryptedVault()
    private let defaults = UserDefaults.standard

    @Published var items: [VaultItem] = []
    @Published var screen: KeyraScreen
    @Published var selected: VaultItem?
    @Published var message: String?
    @Published var biometricEnabled: Bool
    @Published var isSetup: Bool

    private var sessionPassword: String?

    init() {
        let setup = auth.isSetup
        self.isSetup = setup
        self.screen = setup ? .unlock : .onboarding
        self.biometricEnabled = defaults.object(forKey: "biometric_enabled") as? Bool ?? true
    }

    func startCreate() { screen = .unlock }
    func open(_ target: KeyraScreen) { screen = target }
    func addNew() { selected = nil; screen = .add }
    func editSelected() { if selected != nil { screen = .add } }
    func select(_ item: VaultItem) { selected = item; screen = .detail }

    func createVault(password: String) -> Bool {
        guard password.count >= 8 else {
            message = "Glavna lozinka mora imati najmanje 8 znakova."
            return false
        }
        auth.create(password: password)
        isSetup = true
        sessionPassword = password
        items = seedItems()
        try? vault.save(items)
        screen = .vault
        return true
    }

    func unlock(password: String) -> Bool {
        guard auth.verify(password: password) else {
            message = "Glavna lozinka nije ispravna."
            return false
        }
        sessionPassword = password
        load()
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
                    self.load()
                    self.screen = .vault
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
        screen = .unlock
    }

    func save(_ item: VaultItem) {
        var next = item
        next.updatedAt = Date()
        if let index = items.firstIndex(where: { $0.id == item.id }) {
            items[index] = next
        } else {
            items.insert(next, at: 0)
        }
        try? vault.save(items)
        selected = next
        screen = .vault
    }

    func deleteSelected() {
        guard let selected else { return }
        items.removeAll { $0.id == selected.id }
        try? vault.save(items)
        self.selected = nil
        screen = .vault
    }

    func toggleBiometric(_ enabled: Bool) {
        biometricEnabled = enabled
        defaults.set(enabled, forKey: "biometric_enabled")
    }

    func copyBackup() {
        guard let password = sessionPassword else {
            message = "Za sigurnosnu kopiju prvo otključajte trezor glavnom lozinkom."
            return
        }
        do {
            UIPasteboard.general.string = try PortableBackup.encrypt(items, password: password)
            message = "Šifrirana sigurnosna kopija kopirana je u međuspremnik."
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
        do {
            let imported = try PortableBackup.decrypt(text, password: password)
            items = imported
            try vault.save(items)
            message = "Sigurnosna kopija uspješno je uvezena."
        } catch {
            message = "Sigurnosna kopija nije valjana ili lozinka nije odgovarajuća."
        }
    }

    private func load() {
        items = (try? vault.load()) ?? []
    }

    private func seedItems() -> [VaultItem] {
        [
            VaultItem(title: "Google", username: "primjer@keyra.app", password: "K3yra!Google#2026", website: "https://accounts.google.com", notes: "Primjer prijave", category: "Osobno", favorite: true),
            VaultItem(title: "Apple ID", username: "primjer@keyra.app", password: "Appl3!Keyra#2026", website: "https://account.apple.com", category: "Osobno"),
            VaultItem(title: "GitHub", username: "primjer", password: "Git#Keyra!90210", website: "https://github.com", category: "Posao"),
            VaultItem(title: "Home Wi‑Fi", username: "Dnevni boravak", password: "Wifi!Keyra#8821", category: "Osobno"),
            VaultItem(title: "Netflix", username: "primjer@keyra.app", password: "K3yra!Google#2026", website: "https://netflix.com", category: "Zabava"),
            VaultItem(title: "Sigurne bilješke", notes: "Ovdje možete spremati važne privatne bilješke.", category: "Osobno")
        ]
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
    @State private var splash = true

    var body: some View {
        ZStack(alignment: .bottom) {
            midnight.ignoresSafeArea()

            if splash {
                SplashView()
            } else {
                switch store.screen {
                case .onboarding: OnboardingView()
                case .unlock: UnlockView()
                case .vault: VaultView()
                case .collections: CollectionsView()
                case .generator: GeneratorView()
                case .add: AddEditView(store: store)
                case .detail: DetailView()
                case .settings: SettingsView()
                }

                if [.vault, .collections, .generator, .settings].contains(store.screen) {
                    BottomBar()
                }
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
    }
}

struct KeyraMark: View {
    var size: CGFloat = 74

    var body: some View {
        RoundedRectangle(cornerRadius: size / 4)
            .fill(LinearGradient(colors: [cyan, Color(hex: 0x22BDF7), indigo], startPoint: .topLeading, endPoint: .bottomTrailing))
            .overlay(
                Image(systemName: "lock.fill")
                    .font(.system(size: size * 0.38, weight: .bold))
                    .foregroundStyle(midnight)
            )
            .overlay(RoundedRectangle(cornerRadius: size / 4).stroke(ice.opacity(0.5), lineWidth: 1))
            .frame(width: size, height: size)
            .shadow(color: cyan.opacity(0.28), radius: 20)
    }
}

struct SplashView: View {
    var body: some View {
        ZStack {
            LinearGradient(colors: [midnight, Color(hex: 0x071B36), midnight], startPoint: .top, endPoint: .bottom)
                .ignoresSafeArea()
            VStack(spacing: 18) {
                KeyraMark(size: 132)
                Text("Keyra")
                    .font(.system(size: 58, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                Text("SIGURNI UPRAVITELJ LOZINKI")
                    .font(.system(size: 13, weight: .medium))
                    .tracking(3)
                    .foregroundStyle(muted)
                Text("VAŠI KLJUČEVI. VAŠI PODACI. UVIJEK VAŠI.")
                    .font(.system(size: 11, weight: .medium))
                    .tracking(1.8)
                    .foregroundStyle(ice)
                    .padding(.top, 10)
            }
        }
    }
}

struct BrandHeader: View {
    let subtitle: String

    var body: some View {
        HStack(spacing: 14) {
            KeyraMark(size: 56)
            VStack(alignment: .leading, spacing: 1) {
                Text("Keyra")
                    .font(.system(size: 34, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                Text(subtitle)
                    .font(.system(size: 12, weight: .medium))
                    .tracking(3)
                    .foregroundStyle(muted)
            }
            Spacer()
            Image(systemName: "bell")
                .foregroundStyle(.white)
            Text("K")
                .fontWeight(.bold)
                .frame(width: 48, height: 48)
                .overlay(Circle().stroke(cyan, lineWidth: 1))
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 12)
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

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(cyan)
                .frame(width: 48, height: 48)
                .background(Color(hex: 0x0A2D3C))
                .clipShape(RoundedRectangle(cornerRadius: 15))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline).foregroundStyle(.white)
                Text(subtitle).font(.subheadline).foregroundStyle(muted)
            }
            Spacer()
        }
        .padding(14)
        .background(slate.opacity(0.92))
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(cyan.opacity(0.34), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }
}

struct OnboardingView: View {
    @EnvironmentObject var store: KeyraStore

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                KeyraMark(size: 94).padding(.top, 26)
                Text("Keyra")
                    .font(.system(size: 48, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                Text("SIGURNI UPRAVITELJ LOZINKI")
                    .font(.system(size: 12))
                    .tracking(2)
                    .foregroundStyle(muted)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Sigurniji način")
                        .font(.system(size: 34, weight: .black))
                        .foregroundStyle(.white)
                    Text("upravljanja lozinkama")
                        .font(.system(size: 34, weight: .black))
                        .foregroundStyle(cyan)
                    Text("Čuvajte svoje lozinke, pristupne ključeve i osjetljive podatke na jednom sigurnom mjestu.")
                        .font(.body)
                        .foregroundStyle(muted)
                        .padding(.top, 8)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.top, 16)

                FeatureCard(icon: "lock.fill", title: "Potpuno šifrirano", subtitle: "Vaši podaci ostaju na vašem uređaju.")
                FeatureCard(icon: "fingerprint", title: "Privatnost u osnovi", subtitle: "Stvoreno za vaš mir.")
                FeatureCard(icon: "iphone", title: "Radi svugdje", subtitle: "Besprijekorno na Androidu i iOS-u.")

                Button {
                    store.startCreate()
                } label: {
                    HStack {
                        Text("Izradi trezor").fontWeight(.bold)
                        Image(systemName: "arrow.right")
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 56)
                }
                .buttonStyle(.plain)
                .foregroundStyle(midnight)
                .background(cyan)
                .clipShape(Capsule())
                .padding(.top, 14)
            }
            .padding(.horizontal, 22)
            .padding(.bottom, 24)
        }
    }
}

struct UnlockView: View {
    @EnvironmentObject var store: KeyraStore
    @State private var password = ""
    @State private var confirm = ""
    @State private var reveal = false

    private var creating: Bool { !store.isSetup }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                KeyraMark(size: 90).padding(.top, 30)
                Text("Keyra")
                    .font(.system(size: 48, weight: .black, design: .rounded))
                    .foregroundStyle(.white)
                Text("SIGURNI UPRAVITELJ LOZINKI")
                    .font(.system(size: 12))
                    .tracking(2)
                    .foregroundStyle(muted)

                GlassCard {
                    Text(creating ? "Izradite trezor" : "Otključajte trezor")
                        .font(.system(size: 31, weight: .black))
                        .foregroundStyle(.white)
                    Text(creating ? "Postavite glavnu lozinku kojom ćete otključavati svoj trezor." : "Unesite glavnu lozinku kako biste pristupili svom sigurnom trezoru.")
                        .foregroundStyle(muted)

                    SecretField(title: "Glavna lozinka", text: $password, reveal: $reveal)
                    if creating {
                        SecretField(title: "Ponovite glavnu lozinku", text: $confirm, reveal: $reveal)
                    }

                    Button {
                        if creating {
                            if password != confirm { store.message = "Lozinke se ne podudaraju." }
                            else { _ = store.createVault(password: password) }
                        } else {
                            _ = store.unlock(password: password)
                        }
                    } label: {
                        HStack {
                            Image(systemName: "lock.fill")
                            Text(creating ? "Izradi trezor" : "Otključaj").fontWeight(.bold)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 54)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(midnight)
                    .background(cyan)
                    .clipShape(Capsule())

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
            .padding(24)
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
        HStack {
            BottomItem(icon: "house", title: "Trezor", screen: .vault)
            BottomItem(icon: "arrow.triangle.2.circlepath", title: "Generator", screen: .generator)
            BottomItem(icon: "square.grid.2x2", title: "Kolekcije", screen: .collections)
            BottomItem(icon: "gearshape", title: "Postavke", screen: .settings)
        }
        .padding(.vertical, 8)
        .background(slate.opacity(0.97))
        .overlay(RoundedRectangle(cornerRadius: 24).stroke(ice.opacity(0.25), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 24))
        .padding(.horizontal, 14)
        .padding(.bottom, 4)
    }

    @ViewBuilder
    private func BottomItem(icon: String, title: String, screen: KeyraScreen) -> some View {
        Button {
            store.open(screen)
        } label: {
            VStack(spacing: 3) {
                Image(systemName: icon)
                    .font(.title3)
                Text(title).font(.caption)
            }
            .foregroundStyle(store.screen == screen ? cyan : muted)
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.plain)
    }
}

struct VaultView: View {
    @EnvironmentObject var store: KeyraStore
    @State private var search = ""
    @State private var filter = "Sve"

    private var duplicates: Set<UUID> {
        let grouped = Dictionary(grouping: store.items.filter { !$0.password.isEmpty }, by: { $0.password })
        return Set(grouped.values.filter { $0.count > 1 }.flatMap { $0.map(\.id) })
    }

    private var filtered: [VaultItem] {
        store.items.filter { item in
            let filterOK = filter == "Sve" || item.category == filter || (filter == "Favoriti" && item.favorite)
            let searchOK = search.isEmpty || item.title.localizedCaseInsensitiveContains(search) || item.username.localizedCaseInsensitiveContains(search)
            return filterOK && searchOK
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "MOJ TREZOR")

            HStack {
                Image(systemName: "magnifyingglass").foregroundStyle(ice)
                TextField("Pretražite svoj trezor...", text: $search)
                    .foregroundStyle(.white)
            }
            .padding()
            .background(slate)
            .overlay(RoundedRectangle(cornerRadius: 24).stroke(ice.opacity(0.35), lineWidth: 1))
            .clipShape(RoundedRectangle(cornerRadius: 24))
            .padding(.horizontal, 18)

            ScrollView(.horizontal, showsIndicators: false) {
                HStack {
                    ForEach(["Sve","Osobno","Posao","Zabava","Favoriti"], id: \.self) { value in
                        Button(value) { filter = value }
                            .buttonStyle(.plain)
                            .foregroundStyle(filter == value ? midnight : .white)
                            .padding(.horizontal, 15)
                            .padding(.vertical, 9)
                            .background(filter == value ? cyan : slate)
                            .clipShape(Capsule())
                            .overlay(Capsule().stroke(ice.opacity(0.25), lineWidth: 1))
                    }
                }
                .padding(.horizontal, 18)
                .padding(.vertical, 10)
            }

            HStack(spacing: 10) {
                Summary(value: "\(store.items.count)", label: "Ukupno", accent: cyan)
                Summary(value: "\(store.items.filter { !$0.password.isEmpty && $0.password.count < 12 }.count)", label: "Slabe", accent: danger)
                Summary(value: "\(duplicates.count)", label: "Ponovljene", accent: indigo)
            }
            .padding(.horizontal, 18)

            HStack {
                Text("Vaše stavke")
                    .font(.system(size: 28, weight: .black))
                    .foregroundStyle(.white)
                Spacer()
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
                        Text("Nema stavki za prikaz.")
                            .foregroundStyle(muted)
                            .padding(40)
                    }
                }
                .padding(.horizontal, 18)
                .padding(.bottom, 100)
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

    private var state: (String, Color) {
        if duplicated { return ("Ponovno korištena", danger) }
        if !item.password.isEmpty && item.password.count < 12 { return ("Ažurirajte", warn) }
        return ("Snažna", good)
    }

    var body: some View {
        HStack(spacing: 12) {
            Text(String(item.title.prefix(1)).uppercased())
                .font(.title3.bold())
                .foregroundStyle(cyan)
                .frame(width: 48, height: 48)
                .background(Color(hex: 0x0B3551))
                .clipShape(RoundedRectangle(cornerRadius: 14))
            VStack(alignment: .leading, spacing: 3) {
                Text(item.title).font(.headline).foregroundStyle(.white)
                Text(item.username.isEmpty ? item.category : item.username)
                    .font(.subheadline).foregroundStyle(muted)
            }
            Spacer()
            Text(state.0)
                .font(.caption)
                .foregroundStyle(state.1)
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(state.1.opacity(0.12))
                .overlay(Capsule().stroke(state.1.opacity(0.8), lineWidth: 1))
                .clipShape(Capsule())
        }
        .padding(14)
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(ice.opacity(0.18), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }
}

struct CollectionsView: View {
    @EnvironmentObject var store: KeyraStore

    let categories: [(String, Color)] = [
        ("Osobno", Color(hex: 0x00AEE8)),
        ("Posao", indigo),
        ("Financije", Color(hex: 0x00D8A1)),
        ("Društvene mreže", Color(hex: 0xFF3A7A)),
        ("Kupovina", Color(hex: 0xFFC026)),
        ("Putovanja", Color(hex: 0x00B8FF)),
        ("Zdravlje", Color(hex: 0x9C6CFF)),
        ("Ostalo", muted)
    ]

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

            ScrollView {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 10) {
                    ForEach(categories.indices, id: \.self) { index in
                        let name = categories[index].0
                        let accent = categories[index].1
                        VStack(alignment: .leading, spacing: 4) {
                            Text(name).font(.headline).foregroundStyle(.white)
                            Text("\(store.items.filter { $0.category == name }.count) stavki")
                                .font(.subheadline).foregroundStyle(muted)
                        }
                        .frame(maxWidth: .infinity, minHeight: 58, alignment: .leading)
                        .padding(16)
                        .background(accent.opacity(0.13))
                        .overlay(RoundedRectangle(cornerRadius: 20).stroke(accent.opacity(0.8), lineWidth: 1))
                        .clipShape(RoundedRectangle(cornerRadius: 20))
                    }
                }
                .padding(18)

                VStack(alignment: .leading, spacing: 10) {
                    Text("Nedavne bilješke")
                        .font(.title2.bold())
                        .foregroundStyle(.white)
                    Text("Vaše najnovije bilješke i sigurne informacije.")
                        .foregroundStyle(muted)
                    ForEach(store.items.filter { !$0.notes.isEmpty }.prefix(3)) { item in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(item.title).fontWeight(.bold).foregroundStyle(.white)
                            Text(item.notes).lineLimit(1).foregroundStyle(muted)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(14)
                        .background(slate)
                        .clipShape(RoundedRectangle(cornerRadius: 18))
                    }
                }
                .padding(.horizontal, 18)
                .padding(.bottom, 100)
            }
        }
    }
}

struct GeneratorView: View {
    @State private var length = 16.0
    @State private var upper = true
    @State private var lower = true
    @State private var numbers = true
    @State private var symbols = true
    @State private var password = PasswordTools.generate(length: 16, upper: true, lower: true, numbers: true, symbols: true)

    private func refresh() {
        password = PasswordTools.generate(length: Int(length), upper: upper, lower: lower, numbers: numbers, symbols: symbols)
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
                            .font(.system(size: 26, weight: .bold, design: .monospaced))
                            .foregroundStyle(.white)
                            .minimumScaleFactor(0.65)
                            .lineLimit(1)
                        ProgressView(value: 0.9)
                            .tint(cyan)
                        Text("Vrlo snažna").fontWeight(.bold).foregroundStyle(good)
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
                        GeneratorToggle(title: "Velika slova (A–Z)", value: $upper, refresh: refresh)
                        GeneratorToggle(title: "Mala slova (a–z)", value: $lower, refresh: refresh)
                        GeneratorToggle(title: "Brojevi (0–9)", value: $numbers, refresh: refresh)
                        GeneratorToggle(title: "Simboli (!@#...)", value: $symbols, refresh: refresh)
                    }

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
                .padding(18)
                .padding(.bottom, 90)
            }
        }
    }
}

struct GeneratorToggle: View {
    let title: String
    @Binding var value: Bool
    let refresh: () -> Void

    var body: some View {
        Toggle(title, isOn: $value)
            .tint(cyan)
            .foregroundStyle(.white)
            .onChange(of: value) { _, _ in refresh() }
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
    @State private var reveal = false

    private let original: VaultItem?

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
                Text("Keyra").font(.title.bold()).foregroundStyle(.white)
                Spacer()
            }
            .padding()

            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    Text(original == nil ? "Dodaj prijavu" : "Uredi stavku")
                        .font(.system(size: 38, weight: .black))
                        .foregroundStyle(.white)
                    Text("Sigurno spremite svoje vjerodajnice")
                        .foregroundStyle(muted)

                    KeyraField(title: "Naslov", text: $title)
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

                    KeyraField(title: "Bilješke (nije obavezno)", text: $notes, axis: .vertical)

                    Toggle("Favorit", isOn: $favorite)
                        .tint(cyan)
                        .foregroundStyle(.white)

                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack {
                            ForEach(["Osobno","Posao","Financije","Zabava","Putovanja","Ostalo"], id: \.self) { value in
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
                        guard !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                            store.message = "Unesite naslov stavke."
                            return
                        }
                        store.save(
                            VaultItem(
                                id: original?.id ?? UUID(),
                                title: title,
                                username: username,
                                password: password,
                                website: website,
                                notes: notes,
                                category: category,
                                favorite: favorite
                            )
                        )
                    } label: {
                        Label("Spremi", systemImage: "lock.fill")
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
    @State private var reveal = false

    var body: some View {
        if let item = store.selected {
            VStack(spacing: 0) {
                HStack {
                    Button { store.open(.vault) } label: {
                        Image(systemName: "chevron.left").font(.title2).foregroundStyle(.white)
                    }
                    VStack(alignment: .leading) {
                        Text(item.title).font(.system(size: 34, weight: .black)).foregroundStyle(.white)
                        Text("Prijava • \(item.category)").foregroundStyle(muted)
                    }
                    Spacer()
                    if item.favorite { Image(systemName: "star.fill").foregroundStyle(warn) }
                }
                .padding(18)

                ScrollView {
                    VStack(spacing: 10) {
                        if !item.website.isEmpty {
                            DetailRow(icon: "link", title: "Web-stranica", value: item.website)
                        }
                        if !item.username.isEmpty {
                            DetailRow(icon: "person", title: "Korisničko ime / e-pošta", value: item.username) {
                                UIPasteboard.general.string = item.username
                                store.message = "Korisničko ime kopirano je."
                            }
                        }
                        if !item.password.isEmpty {
                            DetailRow(icon: "lock", title: "Lozinka", value: reveal ? item.password : "••••••••••••••") {
                                reveal.toggle()
                            }
                        }
                        if !item.notes.isEmpty {
                            DetailRow(icon: "doc.text", title: "Bilješke", value: item.notes)
                        }

                        HStack {
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

                            Button {
                                store.deleteSelected()
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
                    .padding(18)
                }
            }
        }
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

    var body: some View {
        VStack(spacing: 0) {
            BrandHeader(subtitle: "POSTAVKE I SIGURNOST")
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    SectionLabel("RAČUN I SIGURNOST")
                    SettingRow(icon: "fingerprint", title: "Biometrijsko otključavanje", subtitle: "Brz i siguran pristup trezoru.") {
                        Toggle("", isOn: Binding(get: { store.biometricEnabled }, set: { store.toggleBiometric($0) }))
                            .labelsHidden()
                            .tint(cyan)
                    }
                    SettingRow(icon: "shield.checkered", title: "Provjera sigurnosti", subtitle: "Pronađite slabe i ponovljene lozinke.")

                    SectionLabel("UPRAVLJANJE PODACIMA")
                    SettingRow(icon: "square.and.arrow.up", title: "Kopiraj sigurnosnu kopiju", subtitle: "Stvorite šifriranu kopiju trezora.") {
                        Button { store.copyBackup() } label: {
                            Image(systemName: "doc.on.doc").foregroundStyle(cyan)
                        }.buttonStyle(.plain)
                    }
                    SettingRow(icon: "square.and.arrow.down", title: "Uvezi sigurnosnu kopiju", subtitle: "Vratite šifriranu kopiju iz međuspremnika.") {
                        Button { store.importBackup() } label: {
                            Image(systemName: "arrow.down.doc").foregroundStyle(cyan)
                        }.buttonStyle(.plain)
                    }

                    SectionLabel("PREFERENCIJE")
                    SettingRow(icon: "moon", title: "Tamni način", subtitle: "Čistije i ugodnije iskustvo za oči.")

                    SectionLabel("SIGURNOST I PRIVATNOST")
                    SettingRow(icon: "info.circle", title: "O aplikaciji Keyra", subtitle: "Verzija 0.1.0 • Vaši ključevi. Vaši podaci. Uvijek vaši.")

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
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundStyle(cyan)
                .frame(width: 48, height: 48)
                .background(Color(hex: 0x0B3551))
                .clipShape(RoundedRectangle(cornerRadius: 14))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline).foregroundStyle(.white)
                Text(subtitle).font(.subheadline).foregroundStyle(muted)
            }
            Spacer()
            trailing
        }
        .padding(14)
        .background(slate)
        .overlay(RoundedRectangle(cornerRadius: 20).stroke(ice.opacity(0.18), lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 20))
    }
}

extension SettingRow where Trailing == EmptyView {
    init(icon: String, title: String, subtitle: String) {
        self.init(icon: icon, title: title, subtitle: subtitle) { EmptyView() }
    }
}
